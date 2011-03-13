/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2008 Oswald Buddenhagen <ossi@users.sf.net>
 * Copyright (C) 2004 Theodore Y. Ts'o <tytso@mit.edu>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * As a special exception, mbsync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

/* This must come before isync.h to avoid our #define S messing up
 * blowfish.h on MacOS X. */
#include <config.h>
#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/hmac.h>
#endif

#include "isync.h"

#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct imap_server_conf {
	struct imap_server_conf *next;
	char *name;
	char *tunnel;
	char *host;
	int port;
	char *user;
	char *pass;
#ifdef HAVE_LIBSSL
	char *cert_file;
	unsigned use_imaps:1;
	unsigned require_ssl:1;
	unsigned use_sslv2:1;
	unsigned use_sslv3:1;
	unsigned use_tlsv1:1;
	unsigned require_cram:1;
	X509_STORE *cert_store;
#endif
} imap_server_conf_t;

typedef struct imap_store_conf {
	store_conf_t gen;
	imap_server_conf_t *server;
	unsigned use_namespace:1;
} imap_store_conf_t;

typedef struct imap_message {
	message_t gen;
/*	int seq; will be needed when expunges are tracked */
} imap_message_t;

#define NIL	(void*)0x1
#define LIST	(void*)0x2

typedef struct _list {
	struct _list *next, *child;
	char *val;
	int len;
} list_t;

typedef struct {
	int fd;
#ifdef HAVE_LIBSSL
	SSL *ssl;
#endif
} Socket_t;

typedef struct {
	Socket_t sock;
	int bytes;
	int offset;
	char buf[1024];
} buffer_t;

struct imap_cmd;
#define max_in_progress 50 /* make this configurable? */

typedef struct imap_store {
	store_t gen;
	const char *prefix;
	int ref_count;
	int uidnext; /* from SELECT responses */
	unsigned trashnc:1; /* trash folder's existence is not confirmed yet */
	unsigned got_namespace:1;
	list_t *ns_personal, *ns_other, *ns_shared; /* NAMESPACE info */
	message_t **msgapp; /* FETCH results */
	unsigned caps; /* CAPABILITY results */
	/* command queue */
	int nexttag, num_in_progress, literal_pending;
	struct imap_cmd *in_progress, **in_progress_append;
#ifdef HAVE_LIBSSL
	SSL_CTX *SSLContext;
#endif

	/* Used during sequential operations like connect */
	enum { GreetingPending = 0, GreetingBad, GreetingOk, GreetingPreauth } greeting;
	union {
		void (*imap_open)( store_t *srv, void *aux );
	} callbacks;
	void *callback_aux;

	buffer_t buf; /* this is BIG, so put it last */
} imap_store_t;

struct imap_cmd {
	struct imap_cmd *next;
	char *cmd;
	int tag;

	struct {
		/* Will be called on each continuation request until it resets this pointer.
		 * Needs to invoke bad_callback and return -1 on error, otherwise return 0. */
		int (*cont)( imap_store_t *ctx, struct imap_cmd *cmd, const char *prompt );
		void (*done)( imap_store_t *ctx, struct imap_cmd *cmd, int response );
		char *data;
		int data_len;
		int uid; /* to identify fetch responses */
		unsigned
			to_trash:1, /* we are storing to trash, not current. */
			create:1, /* create the mailbox if we get an error ... */
			trycreate:1; /* ... but only if this is true or the server says so. */
	} param;
};

struct imap_cmd_simple {
	struct imap_cmd gen;
	void (*callback)( int sts, void *aux );
	void *callback_aux;
};

struct imap_cmd_fetch_msg {
	struct imap_cmd_simple gen;
	msg_data_t *msg_data;
};

struct imap_cmd_out_uid {
	struct imap_cmd gen;
	void (*callback)( int sts, int uid, void *aux );
	void *callback_aux;
	int out_uid;
};

struct imap_cmd_refcounted_state {
	void (*callback)( int sts, void *aux );
	void *callback_aux;
	int ref_count;
	int ret_val;
};

struct imap_cmd_refcounted {
	struct imap_cmd gen;
	struct imap_cmd_refcounted_state *state;
};

#define CAP(cap) (ctx->caps & (1 << (cap)))

enum CAPABILITY {
	NOLOGIN = 0,
	UIDPLUS,
	LITERALPLUS,
	NAMESPACE,
#ifdef HAVE_LIBSSL
	CRAM,
	STARTTLS,
#endif
};

static const char *cap_list[] = {
	"LOGINDISABLED",
	"UIDPLUS",
	"LITERAL+",
	"NAMESPACE",
#ifdef HAVE_LIBSSL
	"AUTH=CRAM-MD5",
	"STARTTLS",
#endif
};

#define RESP_OK       0
#define RESP_NO       1
#define RESP_CANCEL   2

static int get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd );

static INLINE void imap_ref( imap_store_t *ctx ) { ++ctx->ref_count; }
static int imap_deref( imap_store_t *ctx );

static void imap_invoke_bad_callback( imap_store_t *ctx );

static const char *Flags[] = {
	"Draft",
	"Flagged",
	"Answered",
	"Seen",
	"Deleted",
};

#ifdef HAVE_LIBSSL
/* Some of this code is inspired by / lifted from mutt. */

static int
compare_certificates( X509 *cert, X509 *peercert,
                      unsigned char *peermd, unsigned peermdlen )
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned mdlen;

	/* Avoid CPU-intensive digest calculation if the certificates are
	 * not even remotely equal. */
	if (X509_subject_name_cmp( cert, peercert ) ||
	    X509_issuer_name_cmp( cert, peercert ))
		return -1;

	if (!X509_digest( cert, EVP_sha1(), md, &mdlen ) ||
	    peermdlen != mdlen || memcmp( peermd, md, mdlen ))
		return -1;

	return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x00904000L
#define READ_X509_KEY(fp, key) PEM_read_X509( fp, key, 0, 0 )
#else
#define READ_X509_KEY(fp, key) PEM_read_X509( fp, key, 0 )
#endif

/* this gets called when a certificate is to be verified */
static int
verify_cert( imap_store_t *ctx )
{
	imap_server_conf_t *srvc = ((imap_store_conf_t *)ctx->gen.conf)->server;
	SSL *ssl = ctx->buf.sock.ssl;
	X509 *cert, *lcert;
	BIO *bio;
	FILE *fp;
	int err;
	unsigned n, i;
	X509_STORE_CTX xsc;
	char buf[256];
	unsigned char md[EVP_MAX_MD_SIZE];

	cert = SSL_get_peer_certificate( ssl );
	if (!cert) {
		error( "Error, no server certificate\n" );
		return -1;
	}

	while (srvc->cert_file) { // So break works
		if (X509_cmp_current_time( X509_get_notBefore( cert )) >= 0) {
			error( "Server certificate is not yet valid" );
			break;
		}
		if (X509_cmp_current_time( X509_get_notAfter( cert )) <= 0) {
			error( "Server certificate has expired" );
			break;
		}
		if (!X509_digest( cert, EVP_sha1(), md, &n )) {
			error( "*** Unable to calculate digest\n" );
			break;
		}
		if (!(fp = fopen( srvc->cert_file, "rt" ))) {
			error( "Unable to load CertificateFile '%s': %s\n",
			       srvc->cert_file, strerror( errno ) );
			return 0;
		}
		err = -1;
		for (lcert = 0; READ_X509_KEY( fp, &lcert ); )
			if (!(err = compare_certificates( lcert, cert, md, n )))
				break;
		X509_free( lcert );
		fclose( fp );
		if (!err)
			return 0;
		break;
	}

	if (!srvc->cert_store) {
		if (!(srvc->cert_store = X509_STORE_new())) {
			error( "Error creating certificate store\n" );
			return -1;
		}
		if (!X509_STORE_set_default_paths( srvc->cert_store ))
			warn( "Error while loading default certificate files: %s\n",
			      ERR_error_string( ERR_get_error(), 0 ) );
		if (!srvc->cert_file) {
			info( "Note: CertificateFile not defined\n" );
		} else if (!X509_STORE_load_locations( srvc->cert_store, srvc->cert_file, 0 )) {
			error( "Error while loading certificate file '%s': %s\n",
			       srvc->cert_file, ERR_error_string( ERR_get_error(), 0 ) );
			return -1;
		}
	}

	X509_STORE_CTX_init( &xsc, srvc->cert_store, cert, 0 );
	err = X509_verify_cert( &xsc ) > 0 ? 0 : X509_STORE_CTX_get_error( &xsc );
	X509_STORE_CTX_cleanup( &xsc );
	if (!err)
		return 0;
	error( "Error, can't verify certificate: %s (%d)\n",
	       X509_verify_cert_error_string( err ), err );

	X509_NAME_oneline( X509_get_subject_name( cert ), buf, sizeof(buf) );
	info( "\nSubject: %s\n", buf );
	X509_NAME_oneline( X509_get_issuer_name( cert ), buf, sizeof(buf) );
	info( "Issuer:  %s\n", buf );
	bio = BIO_new( BIO_s_mem() );
	ASN1_TIME_print( bio, X509_get_notBefore( cert ) );
	memset( buf, 0, sizeof(buf) );
	BIO_read( bio, buf, sizeof(buf) - 1 );
	info( "Valid from: %s\n", buf );
	ASN1_TIME_print( bio, X509_get_notAfter( cert ) );
	memset( buf, 0, sizeof(buf) );
	BIO_read( bio, buf, sizeof(buf) - 1 );
	BIO_free( bio );
	info( "      to:   %s\n", buf );
	if (!X509_digest( cert, EVP_md5(), md, &n )) {
		error( "*** Unable to calculate fingerprint\n" );
	} else {
		info( "Fingerprint: " );
		for (i = 0; i < n; i += 2)
			info( "%02X%02X ", md[i], md[i + 1] );
		info( "\n" );
	}

	fputs( "\nAccept certificate? [y/N]: ",  stderr );
	if (fgets( buf, sizeof(buf), stdin ) && (buf[0] == 'y' || buf[0] == 'Y'))
		return 0;
	return -1;
}

static int
init_ssl_ctx( imap_store_t *ctx )
{
	imap_server_conf_t *srvc = ((imap_store_conf_t *)ctx->gen.conf)->server;
	const SSL_METHOD *method;
	int options = 0;

	if (srvc->use_tlsv1 && !srvc->use_sslv2 && !srvc->use_sslv3)
		method = TLSv1_client_method();
	else
		method = SSLv23_client_method();
	ctx->SSLContext = SSL_CTX_new( method );

	if (!srvc->use_sslv2)
		options |= SSL_OP_NO_SSLv2;
	if (!srvc->use_sslv3)
		options |= SSL_OP_NO_SSLv3;
	if (!srvc->use_tlsv1)
		options |= SSL_OP_NO_TLSv1;

	SSL_CTX_set_options( ctx->SSLContext, options );

	/* we check the result of the verification after SSL_connect() */
	SSL_CTX_set_verify( ctx->SSLContext, SSL_VERIFY_NONE, 0 );
	return 0;
}
#endif /* HAVE_LIBSSL */

static void
socket_perror( const char *func, Socket_t *sock, int ret )
{
#ifdef HAVE_LIBSSL
	int err;

	if (sock->ssl) {
		switch ((err = SSL_get_error( sock->ssl, ret ))) {
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
			if ((err = ERR_get_error()) == 0) {
				if (ret == 0)
					error( "SSL_%s: got EOF\n", func );
				else
					error( "SSL_%s: %s\n", func, strerror(errno) );
			} else
				error( "SSL_%s: %s\n", func, ERR_error_string( err, 0 ) );
			return;
		default:
			error( "SSL_%s: unhandled SSL error %d\n", func, err );
			break;
		}
		return;
	}
#else
	(void)sock;
#endif
	if (ret < 0)
		perror( func );
	else
		error( "%s: unexpected EOF\n", func );
}

static int
socket_read( Socket_t *sock, char *buf, int len )
{
	int n;

	assert( sock->fd >= 0 );
	n =
#ifdef HAVE_LIBSSL
		sock->ssl ? SSL_read( sock->ssl, buf, len ) :
#endif
		read( sock->fd, buf, len );
	if (n <= 0) {
		socket_perror( "read", sock, n );
		close( sock->fd );
		sock->fd = -1;
	}
	return n;
}

static int
socket_write( Socket_t *sock, char *buf, int len )
{
	int n;

	assert( sock->fd >= 0 );
	n =
#ifdef HAVE_LIBSSL
		sock->ssl ? SSL_write( sock->ssl, buf, len ) :
#endif
		write( sock->fd, buf, len );
	if (n != len) {
		socket_perror( "write", sock, n );
		close( sock->fd );
		sock->fd = -1;
	}
	return n;
}

static int
socket_pending( Socket_t *sock )
{
	int num = -1;

	if (ioctl( sock->fd, FIONREAD, &num ) < 0)
		return -1;
	if (num > 0)
		return num;
#ifdef HAVE_LIBSSL
	if (sock->ssl)
		return SSL_pending( sock->ssl );
#endif
	return 0;
}

/* simple line buffering */
static int
buffer_gets( buffer_t * b, char **s )
{
	int n;
	int start = b->offset;

	*s = b->buf + start;

	for (;;) {
		/* make sure we have enough data to read the \r\n sequence */
		if (b->offset + 1 >= b->bytes) {
			if (start) {
				/* shift down used bytes */
				*s = b->buf;

				assert( start <= b->bytes );
				n = b->bytes - start;

				if (n)
					memmove( b->buf, b->buf + start, n );
				b->offset -= start;
				b->bytes = n;
				start = 0;
			}

			n = socket_read( &b->sock, b->buf + b->bytes,
			                 sizeof(b->buf) - b->bytes );

			if (n <= 0)
				return -1;

			b->bytes += n;
		}

		if (b->buf[b->offset] == '\r') {
			assert( b->offset + 1 < b->bytes );
			if (b->buf[b->offset + 1] == '\n') {
				b->buf[b->offset] = 0;  /* terminate the string */
				b->offset += 2; /* next line */
				if (DFlags & VERBOSE)
					puts( *s );
				return 0;
			}
		}

		b->offset++;
	}
	/* not reached */
}

static struct imap_cmd *
new_imap_cmd( int size )
{
	struct imap_cmd *cmd = nfmalloc( size );
	memset( &cmd->param, 0, sizeof(cmd->param) );
	return cmd;
}

#define INIT_IMAP_CMD(type, cmdp, cb, aux) \
	cmdp = (struct type *)new_imap_cmd( sizeof(*cmdp) ); \
	cmdp->callback = cb; \
	cmdp->callback_aux = aux;

#define INIT_IMAP_CMD_X(type, cmdp, cb, aux) \
	cmdp = (struct type *)new_imap_cmd( sizeof(*cmdp) ); \
	cmdp->gen.callback = cb; \
	cmdp->gen.callback_aux = aux;

static struct imap_cmd *
v_submit_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd,
                   const char *fmt, va_list ap )
{
	int bufl, litplus;
	const char *buffmt;
	char buf[1024];

	assert( ctx );
	assert( ctx->gen.bad_callback );
	assert( cmd );
	assert( cmd->param.done );

	while (ctx->literal_pending)
		if (get_cmd_result( ctx, 0 ) == RESP_CANCEL)
			goto bail2;

	cmd->tag = ++ctx->nexttag;
	if (fmt)
		nfvasprintf( &cmd->cmd, fmt, ap );
	if (!cmd->param.data) {
		buffmt = "%d %s\r\n";
		litplus = 0;
	} else if ((cmd->param.to_trash && ctx->trashnc) || !CAP(LITERALPLUS)) {
		buffmt = "%d %s{%d}\r\n";
		litplus = 0;
	} else {
		buffmt = "%d %s{%d+}\r\n";
		litplus = 1;
	}
	bufl = nfsnprintf( buf, sizeof(buf), buffmt,
	                   cmd->tag, cmd->cmd, cmd->param.data_len );
	if (DFlags & VERBOSE) {
		if (ctx->num_in_progress)
			printf( "(%d in progress) ", ctx->num_in_progress );
		if (memcmp( cmd->cmd, "LOGIN", 5 ))
			printf( ">>> %s", buf );
		else
			printf( ">>> %d LOGIN <user> <pass>\n", cmd->tag );
	}
	if (socket_write( &ctx->buf.sock, buf, bufl ) != bufl)
		goto bail;
	if (litplus) {
		if (socket_write( &ctx->buf.sock, cmd->param.data, cmd->param.data_len ) != cmd->param.data_len ||
		    socket_write( &ctx->buf.sock, "\r\n", 2 ) != 2)
			goto bail;
		free( cmd->param.data );
		cmd->param.data = 0;
	} else if (cmd->param.cont || cmd->param.data) {
		ctx->literal_pending = 1;
	}
	cmd->next = 0;
	*ctx->in_progress_append = cmd;
	ctx->in_progress_append = &cmd->next;
	ctx->num_in_progress++;
	return cmd;

  bail:
	imap_invoke_bad_callback( ctx );
  bail2:
	cmd->param.done( ctx, cmd, RESP_CANCEL );
	free( cmd->param.data );
	free( cmd->cmd );
	free( cmd );
	return NULL;
}

static struct imap_cmd *
submit_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd, const char *fmt, ... )
{
	struct imap_cmd *ret;
	va_list ap;

	va_start( ap, fmt );
	ret = v_submit_imap_cmd( ctx, cmd, fmt, ap );
	va_end( ap );
	return ret;
}

static int
imap_exec( imap_store_t *ctx, struct imap_cmd *cmdp,
           void (*done)( imap_store_t *ctx, struct imap_cmd *cmd, int response ),
           const char *fmt, ... )
{
	va_list ap;

	if (!cmdp)
		cmdp = new_imap_cmd( sizeof(*cmdp) );
	cmdp->param.done = done;
	va_start( ap, fmt );
	cmdp = v_submit_imap_cmd( ctx, cmdp, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return RESP_CANCEL;

	return get_cmd_result( ctx, cmdp );
}

static void
transform_box_response( int *response )
{
	switch (*response) {
	case RESP_CANCEL: *response = DRV_CANCELED; break;
	case RESP_NO: *response = DRV_BOX_BAD; break;
	default: *response = DRV_OK; break;
	}
}

static void
imap_done_simple_box( imap_store_t *ctx ATTR_UNUSED,
                      struct imap_cmd *cmd, int response )
{
	struct imap_cmd_simple *cmdp = (struct imap_cmd_simple *)cmd;

	transform_box_response( &response );
	cmdp->callback( response, cmdp->callback_aux );
}

static void
transform_msg_response( int *response )
{
	switch (*response) {
	case RESP_CANCEL: *response = DRV_CANCELED; break;
	case RESP_NO: *response = DRV_MSG_BAD; break;
	default: *response = DRV_OK; break;
	}
}

static void
imap_done_simple_msg( imap_store_t *ctx ATTR_UNUSED,
                      struct imap_cmd *cmd, int response )
{
	struct imap_cmd_simple *cmdp = (struct imap_cmd_simple *)cmd;

	transform_msg_response( &response );
	cmdp->callback( response, cmdp->callback_aux );
}

static struct imap_cmd_refcounted_state *
imap_refcounted_new_state( void (*cb)( int, void * ), void *aux )
{
	struct imap_cmd_refcounted_state *sts = nfmalloc( sizeof(*sts) );
	sts->callback = cb;
	sts->callback_aux = aux;
	sts->ref_count = 1; /* so forced sync does not cause an early exit */
	sts->ret_val = DRV_OK;
	return sts;
}

static struct imap_cmd *
imap_refcounted_new_cmd( struct imap_cmd_refcounted_state *sts )
{
	struct imap_cmd_refcounted *cmd = (struct imap_cmd_refcounted *)new_imap_cmd( sizeof(*cmd) );
	cmd->state = sts;
	sts->ref_count++;
	return &cmd->gen;
}

static void
imap_refcounted_done( struct imap_cmd_refcounted_state *sts )
{
	sts->callback( sts->ret_val, sts->callback_aux );
	free( sts );
}

/*
static void
drain_imap_replies( imap_store_t *ctx )
{
	while (ctx->num_in_progress)
		get_cmd_result( ctx, 0 );
}
*/

static int
process_imap_replies( imap_store_t *ctx )
{
	while (ctx->num_in_progress > max_in_progress ||
	       socket_pending( &ctx->buf.sock ))
		if (get_cmd_result( ctx, 0 ) == RESP_CANCEL)
			return RESP_CANCEL;
	return RESP_OK;
}

static int
is_atom( list_t *list )
{
	return list && list->val && list->val != NIL && list->val != LIST;
}

static int
is_list( list_t *list )
{
	return list && list->val == LIST;
}

static void
free_list( list_t *list )
{
	list_t *tmp;

	for (; list; list = tmp) {
		tmp = list->next;
		if (is_list( list ))
			free_list( list->child );
		else if (is_atom( list ))
			free( list->val );
		free( list );
	}
}

static int
parse_imap_list_l( imap_store_t *ctx, char **sp, list_t **curp, int level )
{
	list_t *cur;
	char *s = *sp, *p;
	int n, bytes;

	for (;;) {
		while (isspace( (unsigned char)*s ))
			s++;
		if (level && *s == ')') {
			s++;
			break;
		}
		*curp = cur = nfmalloc( sizeof(*cur) );
		curp = &cur->next;
		cur->val = 0; /* for clean bail */
		if (*s == '(') {
			/* sublist */
			s++;
			cur->val = LIST;
			if (parse_imap_list_l( ctx, &s, &cur->child, level + 1 ))
				goto bail;
		} else if (ctx && *s == '{') {
			/* literal */
			bytes = cur->len = strtol( s + 1, &s, 10 );
			if (*s != '}')
				goto bail;

			s = cur->val = nfmalloc( cur->len );

			/* dump whats left over in the input buffer */
			n = ctx->buf.bytes - ctx->buf.offset;

			if (n > bytes)
				/* the entire message fit in the buffer */
				n = bytes;

			memcpy( s, ctx->buf.buf + ctx->buf.offset, n );
			s += n;
			bytes -= n;

			/* mark that we used part of the buffer */
			ctx->buf.offset += n;

			/* now read the rest of the message */
			while (bytes > 0) {
				if ((n = socket_read( &ctx->buf.sock, s, bytes )) <= 0)
					goto bail;
				s += n;
				bytes -= n;
			}
			if (DFlags & XVERBOSE) {
				puts( "=========" );
				fwrite( cur->val, cur->len, 1, stdout );
				puts( "=========" );
			}

			if (buffer_gets( &ctx->buf, &s ))
				goto bail;
		} else if (*s == '"') {
			/* quoted string */
			s++;
			p = s;
			for (; *s != '"'; s++)
				if (!*s)
					goto bail;
			cur->len = s - p;
			s++;
			cur->val = nfmalloc( cur->len + 1 );
			memcpy( cur->val, p, cur->len );
			cur->val[cur->len] = 0;
		} else {
			/* atom */
			p = s;
			for (; *s && !isspace( (unsigned char)*s ); s++)
				if (level && *s == ')')
					break;
			cur->len = s - p;
			if (cur->len == 3 && !memcmp ("NIL", p, 3))
				cur->val = NIL;
			else {
				cur->val = nfmalloc( cur->len + 1 );
				memcpy( cur->val, p, cur->len );
				cur->val[cur->len] = 0;
			}
		}

		if (!level)
			break;
		if (!*s)
			goto bail;
	}
	*sp = s;
	*curp = 0;
	return 0;

  bail:
	*curp = 0;
	return -1;
}

static list_t *
parse_imap_list( imap_store_t *ctx, char **sp )
{
	list_t *head;

	if (!parse_imap_list_l( ctx, sp, &head, 0 ))
		return head;
	free_list( head );
	return NULL;
}

static list_t *
parse_list( char **sp )
{
	return parse_imap_list( 0, sp );
}

static int
parse_fetch( imap_store_t *ctx, char *cmd ) /* move this down */
{
	list_t *tmp, *list, *flags;
	char *body = 0;
	imap_message_t *cur;
	msg_data_t *msgdata;
	struct imap_cmd *cmdp;
	int uid = 0, mask = 0, status = 0, size = 0;
	unsigned i;

	list = parse_imap_list( ctx, &cmd );

	if (!is_list( list )) {
		error( "IMAP error: bogus FETCH response\n" );
		free_list( list );
		return -1;
	}

	for (tmp = list->child; tmp; tmp = tmp->next) {
		if (is_atom( tmp )) {
			if (!strcmp( "UID", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp ))
					uid = atoi( tmp->val );
				else
					error( "IMAP error: unable to parse UID\n" );
			} else if (!strcmp( "FLAGS", tmp->val )) {
				tmp = tmp->next;
				if (is_list( tmp )) {
					for (flags = tmp->child; flags; flags = flags->next) {
						if (is_atom( flags )) {
							if (flags->val[0] == '\\') { /* ignore user-defined flags for now */
								if (!strcmp( "Recent", flags->val + 1)) {
									status |= M_RECENT;
									goto flagok;
								}
								for (i = 0; i < as(Flags); i++)
									if (!strcmp( Flags[i], flags->val + 1 )) {
										mask |= 1 << i;
										goto flagok;
									}
								if (flags->val[1] == 'X' && flags->val[2] == '-')
									goto flagok; /* ignore system flag extensions */
								error( "IMAP warning: unknown system flag %s\n", flags->val );
							}
						  flagok: ;
						} else
							error( "IMAP error: unable to parse FLAGS list\n" );
					}
					status |= M_FLAGS;
				} else
					error( "IMAP error: unable to parse FLAGS\n" );
			} else if (!strcmp( "RFC822.SIZE", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp ))
					size = atoi( tmp->val );
				else
					error( "IMAP error: unable to parse RFC822.SIZE\n" );
			} else if (!strcmp( "BODY[]", tmp->val )) {
				tmp = tmp->next;
				if (is_atom( tmp )) {
					body = tmp->val;
					tmp->val = 0;       /* don't free together with list */
					size = tmp->len;
				} else
					error( "IMAP error: unable to parse BODY[]\n" );
			}
		}
	}

	if (body) {
		for (cmdp = ctx->in_progress; cmdp; cmdp = cmdp->next)
			if (cmdp->param.uid == uid)
				goto gotuid;
		error( "IMAP error: unexpected FETCH response (UID %d)\n", uid );
		free_list( list );
		return -1;
	  gotuid:
		msgdata = ((struct imap_cmd_fetch_msg *)cmdp)->msg_data;
		msgdata->data = body;
		msgdata->len = size;
		if (status & M_FLAGS)
			msgdata->flags = mask;
	} else if (uid) { /* ignore async flag updates for now */
		/* XXX this will need sorting for out-of-order (multiple queries) */
		cur = nfcalloc( sizeof(*cur) );
		*ctx->msgapp = &cur->gen;
		ctx->msgapp = &cur->gen.next;
		cur->gen.next = 0;
		cur->gen.uid = uid;
		cur->gen.flags = mask;
		cur->gen.status = status;
		cur->gen.size = size;
	}

	free_list( list );
	return 0;
}

static void
parse_capability( imap_store_t *ctx, char *cmd )
{
	char *arg;
	unsigned i;

	ctx->caps = 0x80000000;
	while ((arg = next_arg( &cmd )))
		for (i = 0; i < as(cap_list); i++)
			if (!strcmp( cap_list[i], arg ))
				ctx->caps |= 1 << i;
}

static int
parse_response_code( imap_store_t *ctx, struct imap_cmd *cmd, char *s )
{
	char *arg, *earg, *p;

	if (*s != '[')
		return RESP_OK;		/* no response code */
	s++;
	if (!(p = strchr( s, ']' ))) {
		error( "IMAP error: malformed response code\n" );
		return RESP_CANCEL;
	}
	*p++ = 0;
	arg = next_arg( &s );
	if (!strcmp( "UIDVALIDITY", arg )) {
		if (!(arg = next_arg( &s )) ||
		    (ctx->gen.uidvalidity = strtoll( arg, &earg, 10 ), *earg))
		{
			error( "IMAP error: malformed UIDVALIDITY status\n" );
			return RESP_CANCEL;
		}
	} else if (!strcmp( "UIDNEXT", arg )) {
		if (!(arg = next_arg( &s )) || (ctx->uidnext = strtol( arg, &p, 10 ), *p)) {
			error( "IMAP error: malformed NEXTUID status\n" );
			return RESP_CANCEL;
		}
	} else if (!strcmp( "CAPABILITY", arg )) {
		parse_capability( ctx, s );
	} else if (!strcmp( "ALERT", arg )) {
		/* RFC2060 says that these messages MUST be displayed
		 * to the user
		 */
		for (; isspace( (unsigned char)*p ); p++);
		error( "*** IMAP ALERT *** %s\n", p );
	} else if (cmd && !strcmp( "APPENDUID", arg )) {
		if (!(arg = next_arg( &s )) ||
		    (ctx->gen.uidvalidity = strtoll( arg, &earg, 10 ), *earg) ||
		    !(arg = next_arg( &s )) ||
		    !(((struct imap_cmd_out_uid *)cmd)->out_uid = atoi( arg )))
		{
			error( "IMAP error: malformed APPENDUID status\n" );
			return RESP_CANCEL;
		}
	}
	return RESP_OK;
}

static void
parse_search( imap_store_t *ctx, char *cmd )
{
	char *arg;
	struct imap_cmd *cmdp;
	int uid;

	if (!(arg = next_arg( &cmd )))
		uid = -1;
	else if (!(uid = atoi( arg ))) {
		error( "IMAP error: malformed SEARCH response\n" );
		return;
	} else if (next_arg( &cmd )) {
		warn( "IMAP warning: SEARCH returns multiple matches\n" );
		uid = -1; /* to avoid havoc */
	}

	/* Find the first command that expects a UID - this is guaranteed
	 * to come in-order, as there are no other means to identify which
	 * SEARCH response belongs to which request.
	 */
	for (cmdp = ctx->in_progress; cmdp; cmdp = cmdp->next)
		if (cmdp->param.uid == -1) {
			((struct imap_cmd_out_uid *)cmdp)->out_uid = uid;
			return;
		}
	error( "IMAP error: unexpected SEARCH response (UID %u)\n", uid );
}

static void
parse_list_rsp( imap_store_t *ctx, char *cmd )
{
	char *arg;
	list_t *list, *lp;
	int l;

	list = parse_list( &cmd );
	if (list->val == LIST)
		for (lp = list->child; lp; lp = lp->next)
			if (is_atom( lp ) && !strcasecmp( lp->val, "\\NoSelect" )) {
				free_list( list );
				return;
			}
	free_list( list );
	(void) next_arg( &cmd ); /* skip delimiter */
	arg = next_arg( &cmd );
	l = strlen( ctx->gen.conf->path );
	if (memcmp( arg, ctx->gen.conf->path, l ))
		return;
	arg += l;
	if (!memcmp( arg + strlen( arg ) - 5, ".lock", 5 )) /* workaround broken servers */
		return;
	add_string_list( &ctx->gen.boxes, arg );
}

struct imap_cmd_trycreate {
	struct imap_cmd gen;
	struct imap_cmd *orig_cmd;
};

static void imap_open_store_greeted( imap_store_t * );
static void get_cmd_result_p2( imap_store_t *, struct imap_cmd *, int );

static int
get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd )
{
	struct imap_cmd *cmdp, **pcmdp;
	char *cmd, *arg, *arg1, *p;
	int n, resp, resp2, tag, greeted;

	greeted = ctx->greeting;
	for (;;) {
		if (buffer_gets( &ctx->buf, &cmd ))
			break;

		arg = next_arg( &cmd );
		if (*arg == '*') {
			arg = next_arg( &cmd );
			if (!arg) {
				error( "IMAP error: unable to parse untagged response\n" );
				break;
			}

			if (!strcmp( "NAMESPACE", arg )) {
				ctx->ns_personal = parse_list( &cmd );
				ctx->ns_other = parse_list( &cmd );
				ctx->ns_shared = parse_list( &cmd );
			} else if (ctx->greeting == GreetingPending && !strcmp( "PREAUTH", arg )) {
				ctx->greeting = GreetingPreauth;
				parse_response_code( ctx, 0, cmd );
			} else if (!strcmp( "OK", arg )) {
				ctx->greeting = GreetingOk;
				parse_response_code( ctx, 0, cmd );
			} else if (!strcmp( "BAD", arg ) || !strcmp( "NO", arg ) || !strcmp( "BYE", arg )) {
				ctx->greeting = GreetingBad;
				parse_response_code( ctx, 0, cmd );
			} else if (!strcmp( "CAPABILITY", arg ))
				parse_capability( ctx, cmd );
			else if (!strcmp( "LIST", arg ))
				parse_list_rsp( ctx, cmd );
			else if (!strcmp( "SEARCH", arg ))
				parse_search( ctx, cmd );
			else if ((arg1 = next_arg( &cmd ))) {
				if (!strcmp( "EXISTS", arg1 ))
					ctx->gen.count = atoi( arg );
				else if (!strcmp( "RECENT", arg1 ))
					ctx->gen.recent = atoi( arg );
				else if(!strcmp ( "FETCH", arg1 )) {
					if (parse_fetch( ctx, cmd ))
						break; /* stream is likely to be useless now */
				}
			} else {
				error( "IMAP error: unrecognized untagged response '%s'\n", arg );
				break; /* this may mean anything, so prefer not to spam the log */
			}
			if (greeted == GreetingPending) {
				imap_ref( ctx );
				imap_open_store_greeted( ctx );
				return imap_deref( ctx ) ? RESP_CANCEL : RESP_OK;
			}
		} else if (!ctx->in_progress) {
			error( "IMAP error: unexpected reply: %s %s\n", arg, cmd ? cmd : "" );
			break; /* this may mean anything, so prefer not to spam the log */
		} else if (*arg == '+') {
			/* This can happen only with the last command underway, as
			   it enforces a round-trip. */
			cmdp = ctx->in_progress;
			if (cmdp->param.data) {
				if (cmdp->param.to_trash)
					ctx->trashnc = 0; /* Can't get NO [TRYCREATE] any more. */
				n = socket_write( &ctx->buf.sock, cmdp->param.data, cmdp->param.data_len );
				free( cmdp->param.data );
				cmdp->param.data = 0;
				if (n != (int)cmdp->param.data_len)
					break;
			} else if (cmdp->param.cont) {
				if (cmdp->param.cont( ctx, cmdp, cmd ))
					break;
			} else {
				error( "IMAP error: unexpected command continuation request\n" );
				break;
			}
			if (socket_write( &ctx->buf.sock, "\r\n", 2 ) != 2)
				break;
			if (!cmdp->param.cont)
				ctx->literal_pending = 0;
			if (!tcmd)
				return RESP_OK;
		} else {
			tag = atoi( arg );
			for (pcmdp = &ctx->in_progress; (cmdp = *pcmdp); pcmdp = &cmdp->next)
				if (cmdp->tag == tag)
					goto gottag;
			error( "IMAP error: unexpected tag %s\n", arg );
			break;
		  gottag:
			if (!(*pcmdp = cmdp->next))
				ctx->in_progress_append = pcmdp;
			ctx->num_in_progress--;
			if (cmdp->param.cont || cmdp->param.data)
				ctx->literal_pending = 0;
			arg = next_arg( &cmd );
			if (!strcmp( "OK", arg )) {
				if (cmdp->param.to_trash)
					ctx->trashnc = 0; /* Can't get NO [TRYCREATE] any more. */
				resp = RESP_OK;
			} else {
				if (!strcmp( "NO", arg )) {
					if (cmdp->param.create &&
					    (cmdp->param.trycreate ||
					     (cmd && !memcmp( cmd, "[TRYCREATE]", 11 ))))
					{ /* SELECT, APPEND or UID COPY */
						struct imap_cmd_trycreate *cmd2 =
							(struct imap_cmd_trycreate *)new_imap_cmd( sizeof(*cmd2) );
						cmd2->orig_cmd = cmdp;
						cmd2->gen.param.done = get_cmd_result_p2;
						p = strchr( cmdp->cmd, '"' );
						if (!submit_imap_cmd( ctx, &cmd2->gen, "CREATE %.*s", strchr( p + 1, '"' ) - p + 1, p ))
							return RESP_CANCEL;
						continue;
					}
					resp = RESP_NO;
				} else /*if (!strcmp( "BAD", arg ))*/
					resp = RESP_CANCEL;
				error( "IMAP command '%s' returned an error: %s %s\n",
				       memcmp( cmdp->cmd, "LOGIN", 5 ) ? cmdp->cmd : "LOGIN <user> <pass>",
				       arg, cmd ? cmd : "" );
			}
			if ((resp2 = parse_response_code( ctx, cmdp, cmd )) > resp)
				resp = resp2;
			imap_ref( ctx );
			if (resp == RESP_CANCEL)
				imap_invoke_bad_callback( ctx );
			cmdp->param.done( ctx, cmdp, resp );
			if (imap_deref( ctx ))
				resp = RESP_CANCEL;
			free( cmdp->param.data );
			free( cmdp->cmd );
			free( cmdp );
			if (resp == RESP_CANCEL || !tcmd || tcmd == cmdp)
				return resp;
		}
	}
	imap_invoke_bad_callback( ctx );
	return RESP_CANCEL;
}

static void
get_cmd_result_p2( imap_store_t *ctx, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_trycreate *cmdp = (struct imap_cmd_trycreate *)cmd;
	struct imap_cmd *ocmd = cmdp->orig_cmd;

	if (response != RESP_OK) {
		ocmd->param.done( ctx, ocmd, response );
		free( ocmd->param.data );
		free( ocmd->cmd );
		free( ocmd );
	} else {
		ctx->uidnext = 0;
		ocmd->param.create = 0;
		submit_imap_cmd( ctx, ocmd, 0 );
	}
}

/******************* imap_cancel_store *******************/

static void
imap_cancel_store( store_t *gctx )
{
	imap_store_t *ctx = (imap_store_t *)gctx;

	free_generic_messages( ctx->gen.msgs );
	free_string_list( ctx->gen.boxes );
	if (ctx->buf.sock.fd >= 0)
		close( ctx->buf.sock.fd );
#ifdef HAVE_LIBSSL
	if (ctx->buf.sock.ssl)
		SSL_free( ctx->buf.sock.ssl );
	if (ctx->SSLContext)
		SSL_CTX_free( ctx->SSLContext );
#endif
	free_list( ctx->ns_personal );
	free_list( ctx->ns_other );
	free_list( ctx->ns_shared );
	imap_deref( ctx );
}

static int
imap_deref( imap_store_t *ctx )
{
	if (!--ctx->ref_count) {
		free( ctx );
		return -1;
	}
	return 0;
}

static void
imap_invoke_bad_callback( imap_store_t *ctx )
{
	ctx->gen.bad_callback( ctx->gen.bad_callback_aux );
}

/******************* imap_disown_store & imap_own_store *******************/

static store_t *unowned;

static void
imap_cancel_unowned( void *gctx )
{
	store_t *store, **storep;

	for (storep = &unowned; (store = *storep); storep = &store->next)
		if (store == gctx) {
			*storep = store->next;
			break;
		}
	imap_cancel_store( gctx );
}

static void
imap_disown_store( store_t *gctx )
{
	free_generic_messages( gctx->msgs );
	gctx->msgs = 0;
	set_bad_callback( gctx, imap_cancel_unowned, gctx );
	gctx->next = unowned;
	unowned = gctx;
}

static store_t *
imap_own_store( store_conf_t *conf )
{
	store_t *store, **storep;

	for (storep = &unowned; (store = *storep); storep = &store->next)
		if (store->conf == conf) {
			*storep = store->next;
			return store;
		}
	return 0;
}

/******************* imap_cleanup *******************/

static void imap_cleanup_p2( imap_store_t *, struct imap_cmd *, int );

static void
imap_cleanup( void )
{
	store_t *ctx, *nctx;

	for (ctx = unowned; ctx; ctx = nctx) {
		nctx = ctx->next;
		set_bad_callback( ctx, (void (*)(void *))imap_cancel_store, ctx );
		imap_exec( (imap_store_t *)ctx, 0, imap_cleanup_p2, "LOGOUT" );
	}
}

static void
imap_cleanup_p2( imap_store_t *ctx,
                 struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_CANCEL)
		imap_cancel_store( &ctx->gen );
}

/******************* imap_open_store *******************/

#ifdef HAVE_LIBSSL
static int
start_tls( imap_store_t *ctx )
{
	int ret;
	static int ssl_inited;

	if (!ssl_inited) {
		SSL_library_init();
		SSL_load_error_strings();
		ssl_inited = 1;
	}

	if (init_ssl_ctx( ctx ))
		return 1;

	ctx->buf.sock.ssl = SSL_new( ctx->SSLContext );
	SSL_set_fd( ctx->buf.sock.ssl, ctx->buf.sock.fd );
	if ((ret = SSL_connect( ctx->buf.sock.ssl )) <= 0) {
		socket_perror( "connect", &ctx->buf.sock, ret );
		return 1;
	}

	/* verify the server certificate */
	if (verify_cert( ctx ))
		return 1;

	info( "Connection is now encrypted\n" );
	return 0;
}

#define ENCODED_SIZE(n) (4*((n+2)/3))

static char
hexchar( unsigned int b )
{
	if (b < 10)
		return '0' + b;
	return 'a' + (b - 10);
}

static void
cram( const char *challenge, const char *user, const char *pass, char **_final, int *_finallen )
{
	unsigned char *response, *final;
	unsigned hashlen;
	int i, clen, rlen, blen, flen, olen;
	unsigned char hash[16];
	char buf[256], hex[33];
	HMAC_CTX hmac;

	HMAC_Init( &hmac, (unsigned char *)pass, strlen( pass ), EVP_md5() );

	clen = strlen( challenge );
	/* response will always be smaller than challenge because we are decoding. */
	response = nfcalloc( 1 + clen );
	rlen = EVP_DecodeBlock( response, (unsigned char *)challenge, clen );
	HMAC_Update( &hmac, response, rlen );
	free( response );

	hashlen = sizeof(hash);
	HMAC_Final( &hmac, hash, &hashlen );
	assert( hashlen == sizeof(hash) );

	hex[32] = 0;
	for (i = 0; i < 16; i++) {
		hex[2 * i] = hexchar( (hash[i] >> 4) & 0xf );
		hex[2 * i + 1] = hexchar( hash[i] & 0xf );
	}

	blen = nfsnprintf( buf, sizeof(buf), "%s %s", user, hex );

	flen = ENCODED_SIZE( blen );
	final = nfmalloc( flen + 1 );
	final[flen] = 0;
	olen = EVP_EncodeBlock( (unsigned char *)final, (unsigned char *)buf, blen );
	assert( olen == flen );

	*_final = (char *)final;
	*_finallen = flen;
}

static int
do_cram_auth( imap_store_t *ctx, struct imap_cmd *cmdp, const char *prompt )
{
	imap_server_conf_t *srvc = ((imap_store_conf_t *)ctx->gen.conf)->server;
	char *resp;
	int n, l;

	cram( prompt, srvc->user, srvc->pass, &resp, &l );

	if (DFlags & VERBOSE)
		printf( ">+> %s\n", resp );
	n = socket_write( &ctx->buf.sock, resp, l );
	free( resp );
	if (n != l)
		return -1;
	cmdp->param.cont = 0;
	return 0;
}
#endif

static void imap_open_store_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_authenticate( imap_store_t * );
#ifdef HAVE_LIBSSL
static void imap_open_store_authenticate_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_authenticate_p3( imap_store_t *, struct imap_cmd *, int );
#endif
static void imap_open_store_authenticate2( imap_store_t * );
static void imap_open_store_authenticate2_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_namespace( imap_store_t * );
static void imap_open_store_namespace_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_namespace2( imap_store_t * );
static void imap_open_store_finalize( imap_store_t * );
#ifdef HAVE_LIBSSL
static void imap_open_store_ssl_bail( imap_store_t * );
#endif
static void imap_open_store_bail( imap_store_t * );

static void
imap_open_store( store_conf_t *conf,
                 void (*cb)( store_t *srv, void *aux ), void *aux )
{
	imap_store_conf_t *cfg = (imap_store_conf_t *)conf;
	imap_server_conf_t *srvc = cfg->server;
	imap_store_t *ctx;
	store_t **ctxp;
	struct hostent *he;
	struct sockaddr_in addr;
	int s, a[2];

	for (ctxp = &unowned; (ctx = (imap_store_t *)*ctxp); ctxp = &ctx->gen.next)
		if (((imap_store_conf_t *)ctx->gen.conf)->server == srvc) {
			*ctxp = ctx->gen.next;
			/* One could ping the server here, but given that the idle timeout
			 * is at least 30 minutes, this sounds pretty pointless. */
			free_string_list( ctx->gen.boxes );
			ctx->gen.boxes = 0;
			ctx->gen.listed = 0;
			ctx->gen.conf = conf;
			ctx->callbacks.imap_open = cb;
			ctx->callback_aux = aux;
			set_bad_callback( &ctx->gen, (void (*)(void *))imap_open_store_bail, ctx );
			imap_open_store_namespace( ctx );
			return;
		}

	ctx = nfcalloc( sizeof(*ctx) );
	ctx->gen.conf = conf;
	ctx->buf.sock.fd = -1;
	ctx->ref_count = 1;
	ctx->callbacks.imap_open = cb;
	ctx->callback_aux = aux;
	set_bad_callback( &ctx->gen, (void (*)(void *))imap_open_store_bail, ctx );
	ctx->in_progress_append = &ctx->in_progress;

	/* open connection to IMAP server */
	if (srvc->tunnel) {
		infon( "Starting tunnel '%s'... ", srvc->tunnel );

		if (socketpair( PF_UNIX, SOCK_STREAM, 0, a )) {
			perror( "socketpair" );
			exit( 1 );
		}

		if (fork() == 0) {
			if (dup2( a[0], 0 ) == -1 || dup2( a[0], 1 ) == -1)
				_exit( 127 );
			close( a[0] );
			close( a[1] );
			execl( "/bin/sh", "sh", "-c", srvc->tunnel, (char *)0 );
			_exit( 127 );
		}

		close (a[0]);

		ctx->buf.sock.fd = a[1];

		info( "ok\n" );
	} else {
		memset( &addr, 0, sizeof(addr) );
		addr.sin_port = srvc->port ? htons( srvc->port ) :
#ifdef HAVE_LIBSSL
		                srvc->use_imaps ? htons( 993 ) :
#endif
		                htons( 143 );
		addr.sin_family = AF_INET;

		infon( "Resolving %s... ", srvc->host );
		he = gethostbyname( srvc->host );
		if (!he) {
			error( "IMAP error: Cannot resolve server '%s'\n", srvc->host );
			goto bail;
		}
		info( "ok\n" );

		addr.sin_addr.s_addr = *((int *) he->h_addr_list[0]);

		s = socket( PF_INET, SOCK_STREAM, 0 );
		if (s < 0) {
			perror( "socket" );
			exit( 1 );
		}

		infon( "Connecting to %s:%hu... ", inet_ntoa( addr.sin_addr ), ntohs( addr.sin_port ) );
		if (connect( s, (struct sockaddr *)&addr, sizeof(addr) )) {
			close( s );
			perror( "connect" );
			goto bail;
		}
		info( "ok\n" );

		ctx->buf.sock.fd = s;
	}

#ifdef HAVE_LIBSSL
	if (srvc->use_imaps) {
		if (start_tls( ctx )) {
			imap_open_store_ssl_bail( ctx );
			return;
		}
	}
#endif
	get_cmd_result( ctx, 0 );
	return;

  bail:
	imap_open_store_bail( ctx );
}

static void
imap_open_store_greeted( imap_store_t *ctx )
{
	if (ctx->greeting == GreetingBad) {
		error( "IMAP error: unknown greeting response\n" );
		imap_open_store_bail( ctx );
		return;
	}

	if (!ctx->caps)
		imap_exec( ctx, 0, imap_open_store_p2, "CAPABILITY" );
	else
		imap_open_store_authenticate( ctx );
}

static void
imap_open_store_p2( imap_store_t *ctx, struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_OK)
		imap_open_store_bail( ctx );
	else
		imap_open_store_authenticate( ctx );
}

static void
imap_open_store_authenticate( imap_store_t *ctx )
{
	if (ctx->greeting != GreetingPreauth) {
#ifdef HAVE_LIBSSL
		imap_store_conf_t *cfg = (imap_store_conf_t *)ctx->gen.conf;
		imap_server_conf_t *srvc = cfg->server;

		if (!srvc->use_imaps && (srvc->use_sslv2 || srvc->use_sslv3 || srvc->use_tlsv1)) {
			/* always try to select SSL support if available */
			if (CAP(STARTTLS)) {
				imap_exec( ctx, 0, imap_open_store_authenticate_p2, "STARTTLS" );
				return;
			} else {
				if (srvc->require_ssl) {
					error( "IMAP error: SSL support not available\n" );
					imap_open_store_bail( ctx );
					return;
				} else {
					warn( "IMAP warning: SSL support not available\n" );
				}
			}
		}
#endif
		imap_open_store_authenticate2( ctx );
	} else {
		imap_open_store_namespace( ctx );
	}
}

#ifdef HAVE_LIBSSL
static void
imap_open_store_authenticate_p2( imap_store_t *ctx, struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_OK)
		imap_open_store_bail( ctx );
	else if (start_tls( ctx ))
		imap_open_store_ssl_bail( ctx );
	else
		imap_exec( ctx, 0, imap_open_store_authenticate_p3, "CAPABILITY" );
}

static void
imap_open_store_authenticate_p3( imap_store_t *ctx, struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_OK)
		imap_open_store_bail( ctx );
	else
		imap_open_store_authenticate2( ctx );
}
#endif

static void
imap_open_store_authenticate2( imap_store_t *ctx )
{
	imap_store_conf_t *cfg = (imap_store_conf_t *)ctx->gen.conf;
	imap_server_conf_t *srvc = cfg->server;
	char *arg;

	info ("Logging in...\n");
	if (!srvc->user) {
		error( "Skipping account %s, no user\n", srvc->name );
		goto bail;
	}
	if (!srvc->pass) {
		char prompt[80];
		sprintf( prompt, "Password (%s): ", srvc->name );
		arg = getpass( prompt );
		if (!arg) {
			perror( "getpass" );
			exit( 1 );
		}
		if (!*arg) {
			error( "Skipping account %s, no password\n", srvc->name );
			goto bail;
		}
		/*
		 * getpass() returns a pointer to a static buffer.  make a copy
		 * for long term storage.
		 */
		srvc->pass = nfstrdup( arg );
	}
#ifdef HAVE_LIBSSL
	if (CAP(CRAM)) {
		struct imap_cmd *cmd = new_imap_cmd( sizeof(*cmd) );

		info( "Authenticating with CRAM-MD5\n" );
		cmd->param.cont = do_cram_auth;
		imap_exec( ctx, cmd, imap_open_store_authenticate2_p2, "AUTHENTICATE CRAM-MD5" );
		return;
	}
	if (srvc->require_cram) {
		error( "IMAP error: CRAM-MD5 authentication is not supported by server\n" );
		goto bail;
	}
#endif
	if (CAP(NOLOGIN)) {
		error( "Skipping account %s, server forbids LOGIN\n", srvc->name );
		goto bail;
	}
#ifdef HAVE_LIBSSL
	if (!ctx->buf.sock.ssl)
#endif
		warn( "*** IMAP Warning *** Password is being sent in the clear\n" );
	imap_exec( ctx, 0, imap_open_store_authenticate2_p2,
	           "LOGIN \"%s\" \"%s\"", srvc->user, srvc->pass );
	return;

  bail:
	imap_open_store_bail( ctx );
}

static void
imap_open_store_authenticate2_p2( imap_store_t *ctx, struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_OK)
		imap_open_store_bail( ctx );
	else
		imap_open_store_namespace( ctx );
}

static void
imap_open_store_namespace( imap_store_t *ctx )
{
	imap_store_conf_t *cfg = (imap_store_conf_t *)ctx->gen.conf;

	ctx->prefix = "";
	if (*cfg->gen.path)
		ctx->prefix = cfg->gen.path;
	else if (cfg->use_namespace && CAP(NAMESPACE)) {
		/* get NAMESPACE info */
		if (!ctx->got_namespace)
			imap_exec( ctx, 0, imap_open_store_namespace_p2, "NAMESPACE" );
		else
			imap_open_store_namespace2( ctx );
		return;
	}
	imap_open_store_finalize( ctx );
}

static void
imap_open_store_namespace_p2( imap_store_t *ctx, struct imap_cmd *cmd ATTR_UNUSED, int response )
{
	if (response != RESP_OK) {
		imap_open_store_bail( ctx );
	} else {
		ctx->got_namespace = 1;
		imap_open_store_namespace2( ctx );
	}
}

static void
imap_open_store_namespace2( imap_store_t *ctx )
{
	/* XXX for now assume personal namespace */
	if (is_list( ctx->ns_personal ) &&
	    is_list( ctx->ns_personal->child ) &&
	    is_atom( ctx->ns_personal->child->child ))
		ctx->prefix = ctx->ns_personal->child->child->val;
	imap_open_store_finalize( ctx );
}

static void
imap_open_store_finalize( imap_store_t *ctx )
{
	set_bad_callback( &ctx->gen, 0, 0 );
	ctx->trashnc = 1;
	ctx->callbacks.imap_open( &ctx->gen, ctx->callback_aux );
}

#ifdef HAVE_LIBSSL
static void
imap_open_store_ssl_bail( imap_store_t *ctx )
{
	/* This avoids that we try to send LOGOUT to an unusable socket. */
	close( ctx->buf.sock.fd );
	ctx->buf.sock.fd = -1;
	imap_open_store_bail( ctx );
}
#endif

static void
imap_open_store_bail( imap_store_t *ctx )
{
	void (*cb)( store_t *srv, void *aux ) = ctx->callbacks.imap_open;
	void *aux = ctx->callback_aux;
	imap_cancel_store( &ctx->gen );
	cb( 0, aux );
}

/******************* imap_prepare_opts *******************/

static void
imap_prepare_opts( store_t *gctx, int opts )
{
	gctx->opts = opts;
}

/******************* imap_select *******************/

static void
imap_select( store_t *gctx, int create,
             void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_simple *cmd;
	const char *prefix;

	free_generic_messages( gctx->msgs );
	gctx->msgs = 0;

	if (!strcmp( gctx->name, "INBOX" )) {
		prefix = "";
	} else {
		prefix = ctx->prefix;
	}

	ctx->uidnext = -1;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	cmd->gen.param.create = create;
	cmd->gen.param.trycreate = 1;
	imap_exec( ctx, &cmd->gen, imap_done_simple_box,
	           "SELECT \"%s%s\"", prefix, gctx->name );
}

/******************* imap_load *******************/

static int imap_submit_load( imap_store_t *, const char *, struct imap_cmd_refcounted_state *,
                             struct imap_cmd ** );
static void imap_load_p2( imap_store_t *, struct imap_cmd *, int );

static void
imap_load( store_t *gctx, int minuid, int maxuid, int *excs, int nexcs,
           void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	int i, j, bl;
	char buf[1000];

	if (!ctx->gen.count) {
		free( excs );
		cb( DRV_OK, aux );
	} else {
		struct imap_cmd *cmd2 = 0;
		struct imap_cmd_refcounted_state *sts = imap_refcounted_new_state( cb, aux );

		ctx->msgapp = &ctx->gen.msgs;
		sort_ints( excs, nexcs );
		for (i = 0; i < nexcs; ) {
			for (bl = 0; i < nexcs && bl < 960; i++) {
				if (bl)
					buf[bl++] = ',';
				bl += sprintf( buf + bl, "%d", excs[i] );
				j = i;
				for (; i + 1 < nexcs && excs[i + 1] == excs[i] + 1; i++) {}
				if (i != j)
					bl += sprintf( buf + bl, ":%d", excs[i] );
			}
			if (imap_submit_load( ctx, buf, sts, &cmd2 ) < 0)
				goto done;
		}
		if (maxuid == INT_MAX)
			maxuid = ctx->uidnext >= 0 ? ctx->uidnext - 1 : 1000000000;
		if (maxuid >= minuid) {
			sprintf( buf, "%d:%d", minuid, maxuid );
			imap_submit_load( ctx, buf, sts, &cmd2 );
		}
	  done:
		free( excs );
		if (!--sts->ref_count)
			imap_refcounted_done( sts );
		else
			get_cmd_result( ctx, cmd2 );
	}
}

static int
imap_submit_load( imap_store_t *ctx, const char *buf, struct imap_cmd_refcounted_state *sts,
                  struct imap_cmd **cmdp )
{
	struct imap_cmd *cmd = imap_refcounted_new_cmd( sts );
	cmd->param.done = imap_load_p2;
	*cmdp = cmd;
	return submit_imap_cmd( ctx, cmd,
	                        "UID FETCH %s (UID%s%s)", buf,
	                        (ctx->gen.opts & OPEN_FLAGS) ? " FLAGS" : "",
	                        (ctx->gen.opts & OPEN_SIZE) ? " RFC822.SIZE" : "" ) ? 0 : -1;
}

static void
imap_load_p2( imap_store_t *ctx ATTR_UNUSED, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_refcounted_state *sts = ((struct imap_cmd_refcounted *)cmd)->state;

	switch (response) {
	case RESP_CANCEL:
		sts->ret_val = DRV_CANCELED;
		break;
	case RESP_NO:
		if (sts->ret_val == DRV_OK) /* Don't override cancelation. */
			sts->ret_val = DRV_BOX_BAD;
		break;
	}
	if (!--sts->ref_count)
		imap_refcounted_done( sts );
}

/******************* imap_fetch_msg *******************/

static void
imap_fetch_msg( store_t *ctx, message_t *msg, msg_data_t *data,
                void (*cb)( int sts, void *aux ), void *aux )
{
	struct imap_cmd_fetch_msg *cmd;

	INIT_IMAP_CMD_X(imap_cmd_fetch_msg, cmd, cb, aux)
	cmd->gen.gen.param.uid = msg->uid;
	cmd->msg_data = data;
	imap_exec( (imap_store_t *)ctx, &cmd->gen.gen, imap_done_simple_msg,
	           "UID FETCH %d (%sBODY.PEEK[])",
	           msg->uid, (msg->status & M_FLAGS) ? "" : "FLAGS " );
}

/******************* imap_set_flags *******************/

static void imap_set_flags_p2( imap_store_t *, struct imap_cmd *, int );

static int
imap_make_flags( int flags, char *buf )
{
	const char *s;
	unsigned i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i)) {
			buf[d++] = ' ';
			buf[d++] = '\\';
			for (s = Flags[i]; *s; s++)
				buf[d++] = *s;
		}
	buf[0] = '(';
	buf[d++] = ')';
	return d;
}

static int
imap_flags_helper( imap_store_t *ctx, int uid, char what, int flags,
                   struct imap_cmd_refcounted_state *sts )
{
	char buf[256];

	struct imap_cmd *cmd = imap_refcounted_new_cmd( sts );
	cmd->param.done = imap_set_flags_p2;
	buf[imap_make_flags( flags, buf )] = 0;
	if (!submit_imap_cmd( ctx, cmd, "UID STORE %d %cFLAGS.SILENT %s", uid, what, buf ))
		return -1;
	return process_imap_replies( ctx ) == RESP_CANCEL ? -1 : 0;
}

static void
imap_set_flags( store_t *gctx, message_t *msg, int uid, int add, int del,
                void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;

	if (msg) {
		uid = msg->uid;
		add &= ~msg->flags;
		del &= msg->flags;
		msg->flags |= add;
		msg->flags &= ~del;
	}
	if (add || del) {
		struct imap_cmd_refcounted_state *sts = imap_refcounted_new_state( cb, aux );
		if ((add && imap_flags_helper( ctx, uid, '+', add, sts ) < 0) ||
		    (del && imap_flags_helper( ctx, uid, '-', del, sts ) < 0)) {}
		if (!--sts->ref_count)
			imap_refcounted_done( sts );
	} else {
		cb( DRV_OK, aux );
	}
}

static void
imap_set_flags_p2( imap_store_t *ctx ATTR_UNUSED, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_refcounted_state *sts = ((struct imap_cmd_refcounted *)cmd)->state;
	switch (response) {
	case RESP_CANCEL:
		sts->ret_val = DRV_CANCELED;
		break;
	case RESP_NO:
		if (sts->ret_val == DRV_OK) /* Don't override cancelation. */
			sts->ret_val = DRV_MSG_BAD;
		break;
	}
	if (!--sts->ref_count)
		imap_refcounted_done( sts );
}

/******************* imap_close *******************/

static void
imap_close( store_t *ctx,
            void (*cb)( int sts, void *aux ), void *aux )
{
	struct imap_cmd_simple *cmd;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	imap_exec( (imap_store_t *)ctx, &cmd->gen, imap_done_simple_box, "CLOSE" );
}

/******************* imap_trash_msg *******************/

static void
imap_trash_msg( store_t *gctx, message_t *msg,
                void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_simple *cmd;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	cmd->gen.param.create = 1;
	cmd->gen.param.to_trash = 1;
	imap_exec( ctx, &cmd->gen, imap_done_simple_msg,
	           "UID COPY %d \"%s%s\"",
	           msg->uid, ctx->prefix, gctx->conf->trash );
}

/******************* imap_store_msg *******************/

static void imap_store_msg_p2( imap_store_t *, struct imap_cmd *, int );

static void
imap_store_msg( store_t *gctx, msg_data_t *data, int to_trash,
                void (*cb)( int sts, int uid, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_out_uid *cmd;
	const char *prefix, *box;
	int d;
	char flagstr[128];

	d = 0;
	if (data->flags) {
		d = imap_make_flags( data->flags, flagstr );
		flagstr[d++] = ' ';
	}
	flagstr[d] = 0;

	INIT_IMAP_CMD(imap_cmd_out_uid, cmd, cb, aux)
	cmd->gen.param.data_len = data->len;
	cmd->gen.param.data = data->data;
	cmd->out_uid = -2;

	if (to_trash) {
		box = gctx->conf->trash;
		prefix = ctx->prefix;
		cmd->gen.param.create = 1;
		cmd->gen.param.to_trash = 1;
	} else {
		box = gctx->name;
		prefix = !strcmp( box, "INBOX" ) ? "" : ctx->prefix;
	}
	imap_exec( ctx, &cmd->gen, imap_store_msg_p2,
	           "APPEND \"%s%s\" %s", prefix, box, flagstr );
}

static void
imap_store_msg_p2( imap_store_t *ctx ATTR_UNUSED, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_out_uid *cmdp = (struct imap_cmd_out_uid *)cmd;

	transform_msg_response( &response );
	cmdp->callback( response, cmdp->out_uid, cmdp->callback_aux );
}

/******************* imap_find_msg *******************/

static void imap_find_msg_p2( imap_store_t *, struct imap_cmd *, int );

static void
imap_find_msg( store_t *gctx, const char *tuid,
               void (*cb)( int sts, int uid, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_out_uid *cmd;

	INIT_IMAP_CMD(imap_cmd_out_uid, cmd, cb, aux)
	cmd->gen.param.uid = -1; /* we're looking for a UID */
	cmd->out_uid = -1; /* in case we get no SEARCH response at all */
	imap_exec( ctx, &cmd->gen, imap_find_msg_p2,
	           "UID SEARCH HEADER X-TUID %." stringify(TUIDL) "s", tuid );
}

static void
imap_find_msg_p2( imap_store_t *ctx ATTR_UNUSED, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_out_uid *cmdp = (struct imap_cmd_out_uid *)cmd;

	transform_msg_response( &response );
	if (response != DRV_OK)
		cmdp->callback( response, -1, cmdp->callback_aux );
	else
		cmdp->callback( cmdp->out_uid <= 0 ? DRV_MSG_BAD : DRV_OK,
		                cmdp->out_uid, cmdp->callback_aux );
}

/******************* imap_list *******************/

static void
imap_list( store_t *gctx,
           void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_simple *cmd;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	imap_exec( ctx, &cmd->gen, imap_done_simple_box,
	           "LIST \"\" \"%s%%\"", ctx->prefix );
}

/******************* imap_cancel *******************/

static void
imap_cancel( store_t *gctx,
             void (*cb)( void *aux ), void *aux )
{
	(void)gctx;
	cb( aux );
}

/******************* imap_commit *******************/

static void
imap_commit( store_t *gctx )
{
	(void)gctx;
}

/******************* imap_parse_store *******************/

imap_server_conf_t *servers, **serverapp = &servers;

static int
imap_parse_store( conffile_t *cfg, store_conf_t **storep, int *err )
{
	imap_store_conf_t *store;
	imap_server_conf_t *server, *srv, sserver;
	int acc_opt = 0;

	if (!strcasecmp( "IMAPAccount", cfg->cmd )) {
		server = nfcalloc( sizeof(*server) );
		server->name = nfstrdup( cfg->val );
		*serverapp = server;
		serverapp = &server->next;
		store = 0;
		*storep = 0;
	} else if (!strcasecmp( "IMAPStore", cfg->cmd )) {
		store = nfcalloc( sizeof(*store) );
		store->gen.driver = &imap_driver;
		store->gen.name = nfstrdup( cfg->val );
		store->use_namespace = 1;
		*storep = &store->gen;
		memset( &sserver, 0, sizeof(sserver) );
		server = &sserver;
	} else
		return 0;

#ifdef HAVE_LIBSSL
	/* this will probably annoy people, but its the best default just in
	 * case people forget to turn it on
	 */
	server->require_ssl = 1;
	server->use_tlsv1 = 1;
#endif

	while (getcline( cfg ) && cfg->cmd) {
		if (!strcasecmp( "Host", cfg->cmd )) {
			/* The imap[s]: syntax is just a backwards compat hack. */
#ifdef HAVE_LIBSSL
			if (!memcmp( "imaps:", cfg->val, 6 )) {
				cfg->val += 6;
				server->use_imaps = 1;
				server->use_sslv2 = 1;
				server->use_sslv3 = 1;
			} else
#endif
			{
				if (!memcmp( "imap:", cfg->val, 5 ))
					cfg->val += 5;
			}
			if (!memcmp( "//", cfg->val, 2 ))
				cfg->val += 2;
			server->host = nfstrdup( cfg->val );
		}
		else if (!strcasecmp( "User", cfg->cmd ))
			server->user = nfstrdup( cfg->val );
		else if (!strcasecmp( "Pass", cfg->cmd ))
			server->pass = nfstrdup( cfg->val );
		else if (!strcasecmp( "Port", cfg->cmd ))
			server->port = parse_int( cfg );
#ifdef HAVE_LIBSSL
		else if (!strcasecmp( "CertificateFile", cfg->cmd )) {
			server->cert_file = expand_strdup( cfg->val );
			if (access( server->cert_file, R_OK )) {
				error( "%s:%d: CertificateFile '%s': %s\n",
				       cfg->file, cfg->line, server->cert_file, strerror( errno ) );
				*err = 1;
			}
		} else if (!strcasecmp( "RequireSSL", cfg->cmd ))
			server->require_ssl = parse_bool( cfg );
		else if (!strcasecmp( "UseIMAPS", cfg->cmd ))
			server->use_imaps = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv2", cfg->cmd ))
			server->use_sslv2 = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv3", cfg->cmd ))
			server->use_sslv3 = parse_bool( cfg );
		else if (!strcasecmp( "UseTLSv1", cfg->cmd ))
			server->use_tlsv1 = parse_bool( cfg );
		else if (!strcasecmp( "RequireCRAM", cfg->cmd ))
			server->require_cram = parse_bool( cfg );
#endif
		else if (!strcasecmp( "Tunnel", cfg->cmd ))
			server->tunnel = nfstrdup( cfg->val );
		else if (store) {
			if (!strcasecmp( "Account", cfg->cmd )) {
				for (srv = servers; srv; srv = srv->next)
					if (srv->name && !strcmp( srv->name, cfg->val ))
						goto gotsrv;
				error( "%s:%d: unknown IMAP account '%s'\n", cfg->file, cfg->line, cfg->val );
				*err = 1;
				continue;
			  gotsrv:
				store->server = srv;
			} else if (!strcasecmp( "UseNamespace", cfg->cmd ))
				store->use_namespace = parse_bool( cfg );
			else if (!strcasecmp( "Path", cfg->cmd ))
				store->gen.path = nfstrdup( cfg->val );
			else
				parse_generic_store( &store->gen, cfg, err );
			continue;
		} else {
			error( "%s:%d: unknown/misplaced keyword '%s'\n", cfg->file, cfg->line, cfg->cmd );
			*err = 1;
			continue;
		}
		acc_opt = 1;
	}
	if (!store || !store->server) {
		if (!server->tunnel && !server->host) {
			if (store)
				error( "IMAP store '%s' has incomplete/missing connection details\n", store->gen.name );
			else
				error( "IMAP account '%s' has incomplete/missing connection details\n", server->name );
			*err = 1;
			return 1;
		}
	}
	if (store) {
		if (!store->server) {
			store->server = nfmalloc( sizeof(sserver) );
			memcpy( store->server, &sserver, sizeof(sserver) );
			store->server->name = store->gen.name;
		} else if (acc_opt) {
			error( "IMAP store '%s' has both Account and account-specific options\n", store->gen.name );
			*err = 1;
		}
	}
	return 1;
}

struct driver imap_driver = {
	DRV_CRLF,
	imap_parse_store,
	imap_cleanup,
	imap_open_store,
	imap_disown_store,
	imap_own_store,
	imap_cancel_store,
	imap_list,
	imap_prepare_opts,
	imap_select,
	imap_load,
	imap_fetch_msg,
	imap_store_msg,
	imap_find_msg,
	imap_set_flags,
	imap_trash_msg,
	imap_close,
	imap_cancel,
	imap_commit,
};
