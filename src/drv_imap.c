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
	unsigned int use_ssl:1;
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
	unsigned /*currentnc:1,*/ trashnc:1;
	int uidnext; /* from SELECT responses */
	unsigned got_namespace:1;
	list_t *ns_personal, *ns_other, *ns_shared; /* NAMESPACE info */
	message_t **msgapp; /* FETCH results */
	unsigned caps, rcaps; /* CAPABILITY results */
	/* command queue */
	int nexttag, num_in_progress, literal_pending;
	struct imap_cmd *in_progress, **in_progress_append;
#ifdef HAVE_LIBSSL
	SSL_CTX *SSLContext;
#endif
	buffer_t buf; /* this is BIG, so put it last */
} imap_store_t;

struct imap_cmd {
	struct imap_cmd *next;
	char *cmd;
	int tag;

	struct {
		int (*cont)( imap_store_t *ctx, struct imap_cmd *cmd, const char *prompt );
		void (*done)( imap_store_t *ctx, struct imap_cmd *cmd, int response );
		void *aux;
		char *data;
		int data_len;
		int uid; /* to identify fetch responses */
		unsigned
			create:1, /* create the mailbox if we get an error ... */
			trycreate:1; /* ... but only if this is true or the server says so. */
	} param;
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

#define RESP_OK    0
#define RESP_NO    1
#define RESP_BAD   2

static int get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd );


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
	SSL_METHOD *method;
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

	if (sock->use_ssl) {
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
		sock->use_ssl ? SSL_read( sock->ssl, buf, len ) :
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
		sock->use_ssl ? SSL_write( sock->ssl, buf, len ) :
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
	if (sock->use_ssl)
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
new_imap_cmd( void )
{
	struct imap_cmd *cmd = nfmalloc( sizeof(*cmd) );
	memset( &cmd->param, 0, sizeof(cmd->param) );
	return cmd;
}

static struct imap_cmd *
v_submit_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd,
                   const char *fmt, va_list ap )
{
	int n, bufl;
	char buf[1024];

	while (ctx->literal_pending)
		get_cmd_result( ctx, 0 );

	if (!cmd)
		cmd = new_imap_cmd();
	cmd->tag = ++ctx->nexttag;
	nfvasprintf( &cmd->cmd, fmt, ap );
	bufl = nfsnprintf( buf, sizeof(buf), cmd->param.data ? CAP(LITERALPLUS) ?
	                   "%d %s{%d+}\r\n" : "%d %s{%d}\r\n" : "%d %s\r\n",
	                   cmd->tag, cmd->cmd, cmd->param.data_len );
	if (DFlags & VERBOSE) {
		if (ctx->num_in_progress)
			printf( "(%d in progress) ", ctx->num_in_progress );
		if (memcmp( cmd->cmd, "LOGIN", 5 ))
			printf( ">>> %s", buf );
		else
			printf( ">>> %d LOGIN <user> <pass>\n", cmd->tag );
	}
	if (socket_write( &ctx->buf.sock, buf, bufl ) != bufl) {
		free( cmd->param.data );
		free( cmd->cmd );
		free( cmd );
		return NULL;
	}
	if (cmd->param.data) {
		if (CAP(LITERALPLUS)) {
			n = socket_write( &ctx->buf.sock, cmd->param.data, cmd->param.data_len );
			free( cmd->param.data );
			if (n != cmd->param.data_len ||
			    (n = socket_write( &ctx->buf.sock, "\r\n", 2 )) != 2)
			{
				free( cmd->cmd );
				free( cmd );
				return NULL;
			}
			cmd->param.data = 0;
		} else
			ctx->literal_pending = 1;
	} else if (cmd->param.cont)
		ctx->literal_pending = 1;
	cmd->next = 0;
	*ctx->in_progress_append = cmd;
	ctx->in_progress_append = &cmd->next;
	ctx->num_in_progress++;
	return cmd;
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
imap_exec( imap_store_t *ctx, struct imap_cmd *cmdp, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	cmdp = v_submit_imap_cmd( ctx, cmdp, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return RESP_BAD;

	return get_cmd_result( ctx, cmdp );
}

static int
imap_exec_b( imap_store_t *ctx, struct imap_cmd *cmdp, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	cmdp = v_submit_imap_cmd( ctx, cmdp, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return DRV_STORE_BAD;

	switch (get_cmd_result( ctx, cmdp )) {
	case RESP_BAD: return DRV_STORE_BAD;
	case RESP_NO: return DRV_BOX_BAD;
	default: return DRV_OK;
	}
}

static int
imap_exec_m( imap_store_t *ctx, struct imap_cmd *cmdp, const char *fmt, ... )
{
	va_list ap;

	va_start( ap, fmt );
	cmdp = v_submit_imap_cmd( ctx, cmdp, fmt, ap );
	va_end( ap );
	if (!cmdp)
		return DRV_STORE_BAD;

	switch (get_cmd_result( ctx, cmdp )) {
	case RESP_BAD: return DRV_STORE_BAD;
	case RESP_NO: return DRV_MSG_BAD;
	default: return DRV_OK;
	}
}

/*
static void
drain_imap_replies( imap_store_t *ctx )
{
	while (ctx->num_in_progress)
		get_cmd_result( ctx, 0 );
}
*/

static void
process_imap_replies( imap_store_t *ctx )
{
	while (ctx->num_in_progress > max_in_progress ||
	       socket_pending( &ctx->buf.sock ))
		get_cmd_result( ctx, 0 );
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
		msgdata = (msg_data_t *)cmdp->param.aux;
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
	ctx->rcaps = ctx->caps;
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
		return RESP_BAD;
	}
	*p++ = 0;
	arg = next_arg( &s );
	if (!strcmp( "UIDVALIDITY", arg )) {
		if (!(arg = next_arg( &s )) ||
		    (ctx->gen.uidvalidity = strtoll( arg, &earg, 10 ), *earg))
		{
			error( "IMAP error: malformed UIDVALIDITY status\n" );
			return RESP_BAD;
		}
	} else if (!strcmp( "UIDNEXT", arg )) {
		if (!(arg = next_arg( &s )) || (ctx->uidnext = strtol( arg, &p, 10 ), *p)) {
			error( "IMAP error: malformed NEXTUID status\n" );
			return RESP_BAD;
		}
	} else if (!strcmp( "CAPABILITY", arg )) {
		parse_capability( ctx, s );
	} else if (!strcmp( "ALERT", arg )) {
		/* RFC2060 says that these messages MUST be displayed
		 * to the user
		 */
		for (; isspace( (unsigned char)*p ); p++);
		error( "*** IMAP ALERT *** %s\n", p );
	} else if (cmd && cmd->param.aux && !strcmp( "APPENDUID", arg )) {
		if (!(arg = next_arg( &s )) ||
		    (ctx->gen.uidvalidity = strtoll( arg, &earg, 10 ), *earg) ||
		    !(arg = next_arg( &s )) || !(*(int *)cmd->param.aux = atoi( arg )))
		{
			error( "IMAP error: malformed APPENDUID status\n" );
			return RESP_BAD;
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
			*(int *)cmdp->param.aux = uid;
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

static int
get_cmd_result( imap_store_t *ctx, struct imap_cmd *tcmd )
{
	struct imap_cmd *cmdp, **pcmdp, *ncmdp;
	char *cmd, *arg, *arg1, *p;
	int n, resp, resp2, tag;

	for (;;) {
		if (buffer_gets( &ctx->buf, &cmd ))
			return RESP_BAD;

		arg = next_arg( &cmd );
		if (*arg == '*') {
			arg = next_arg( &cmd );
			if (!arg) {
				error( "IMAP error: unable to parse untagged response\n" );
				return RESP_BAD;
			}

			if (!strcmp( "NAMESPACE", arg )) {
				ctx->ns_personal = parse_list( &cmd );
				ctx->ns_other = parse_list( &cmd );
				ctx->ns_shared = parse_list( &cmd );
			} else if (!strcmp( "OK", arg ) || !strcmp( "BAD", arg ) ||
			           !strcmp( "NO", arg ) || !strcmp( "BYE", arg )) {
				if ((resp = parse_response_code( ctx, 0, cmd )) != RESP_OK)
					return resp;
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
						return RESP_BAD;
				}
			} else {
				error( "IMAP error: unable to parse untagged response\n" );
				return RESP_BAD;
			}
		} else if (!ctx->in_progress) {
			error( "IMAP error: unexpected reply: %s %s\n", arg, cmd ? cmd : "" );
			return RESP_BAD;
		} else if (*arg == '+') {
			/* This can happen only with the last command underway, as
			   it enforces a round-trip. */
			cmdp = ctx->in_progress;
			if (cmdp->param.data) {
				n = socket_write( &ctx->buf.sock, cmdp->param.data, cmdp->param.data_len );
				free( cmdp->param.data );
				cmdp->param.data = 0;
				if (n != (int)cmdp->param.data_len)
					return RESP_BAD;
			} else if (cmdp->param.cont) {
				if (cmdp->param.cont( ctx, cmdp, cmd ))
					return RESP_BAD;
			} else {
				error( "IMAP error: unexpected command continuation request\n" );
				return RESP_BAD;
			}
			if (socket_write( &ctx->buf.sock, "\r\n", 2 ) != 2)
				return RESP_BAD;
			if (!cmdp->param.cont)
				ctx->literal_pending = 0;
			if (!tcmd)
				return DRV_OK;
		} else {
			tag = atoi( arg );
			for (pcmdp = &ctx->in_progress; (cmdp = *pcmdp); pcmdp = &cmdp->next)
				if (cmdp->tag == tag)
					goto gottag;
			error( "IMAP error: unexpected tag %s\n", arg );
			return RESP_BAD;
		  gottag:
			if (!(*pcmdp = cmdp->next))
				ctx->in_progress_append = pcmdp;
			ctx->num_in_progress--;
			if (cmdp->param.cont || cmdp->param.data)
				ctx->literal_pending = 0;
			arg = next_arg( &cmd );
			if (!strcmp( "OK", arg ))
				resp = DRV_OK;
			else {
				if (!strcmp( "NO", arg )) {
					if (cmdp->param.create && cmd && (cmdp->param.trycreate || !memcmp( cmd, "[TRYCREATE]", 11 ))) { /* SELECT, APPEND or UID COPY */
						p = strchr( cmdp->cmd, '"' );
						if (!submit_imap_cmd( ctx, 0, "CREATE %.*s", strchr( p + 1, '"' ) - p + 1, p )) {
							resp = RESP_BAD;
							goto normal;
						}
						/* not waiting here violates the spec, but a server that does not
						   grok this nonetheless violates it too. */
						ncmdp = nfmalloc( sizeof(*ncmdp) );
						memcpy( &ncmdp->param, &cmdp->param, sizeof(cmdp->param) );
						ncmdp->param.create = 0;
						if (!submit_imap_cmd( ctx, ncmdp, "%s", cmdp->cmd )) {
							resp = RESP_BAD;
							goto normal;
						}
						free( cmdp->cmd );
						free( cmdp );
						if (!tcmd)
							return 0;	/* ignored */
						if (cmdp == tcmd)
							tcmd = ncmdp;
						continue;
					}
					resp = RESP_NO;
				} else /*if (!strcmp( "BAD", arg ))*/
					resp = RESP_BAD;
				error( "IMAP command '%s' returned an error: %s %s\n",
				       memcmp( cmdp->cmd, "LOGIN", 5 ) ? cmdp->cmd : "LOGIN <user> <pass>",
				       arg, cmd ? cmd : "" );
			}
			if ((resp2 = parse_response_code( ctx, cmdp, cmd )) > resp)
				resp = resp2;
		  normal:
			if (cmdp->param.done)
				cmdp->param.done( ctx, cmdp, resp );
			free( cmdp->param.data );
			free( cmdp->cmd );
			free( cmdp );
			if (!tcmd || tcmd == cmdp)
				return resp;
		}
	}
	/* not reached */
}

static void
imap_cancel_store( store_t *gctx )
{
	imap_store_t *ctx = (imap_store_t *)gctx;

	free_generic_messages( gctx->msgs );
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
	free( ctx );
}

static store_t *unowned;

static void
imap_disown_store( store_t *gctx )
{
	free_generic_messages( gctx->msgs );
	gctx->msgs = 0;
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

static void
imap_cleanup( void )
{
	store_t *ctx, *nctx;

	for (ctx = unowned; ctx; ctx = nctx) {
		nctx = ctx->next;
		imap_exec( (imap_store_t *)ctx, 0, "LOGOUT" );
		imap_cancel_store( ctx );
	}
}

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

	ctx->buf.sock.use_ssl = 1;
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

static void
imap_open_store( store_conf_t *conf,
                 void (*cb)( store_t *srv, void *aux ), void *aux )
{
	imap_store_conf_t *cfg = (imap_store_conf_t *)conf;
	imap_server_conf_t *srvc = cfg->server;
	imap_store_t *ctx;
	store_t **ctxp;
	char *arg, *rsp;
	struct hostent *he;
	struct sockaddr_in addr;
	int s, a[2], preauth;
#ifdef HAVE_LIBSSL
	int use_ssl;
#endif

	for (ctxp = &unowned; (ctx = (imap_store_t *)*ctxp); ctxp = &ctx->gen.next)
		if (((imap_store_conf_t *)ctx->gen.conf)->server == srvc) {
			*ctxp = ctx->gen.next;
			/* One could ping the server here, but given that the idle timeout
			 * is at least 30 minutes, this sounds pretty pointless. */
			free_string_list( ctx->gen.boxes );
			ctx->gen.boxes = 0;
			ctx->gen.listed = 0;
			ctx->gen.conf = conf;
			goto final;
		}

	ctx = nfcalloc( sizeof(*ctx) );
	ctx->gen.conf = conf;
	ctx->buf.sock.fd = -1;
	ctx->in_progress_append = &ctx->in_progress;

	/* open connection to IMAP server */
#ifdef HAVE_LIBSSL
	use_ssl = 0;
#endif

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
		if (start_tls( ctx ))
			goto ssl_bail;
		use_ssl = 1;
	}
#endif

	/* read the greeting string */
	if (buffer_gets( &ctx->buf, &rsp ))
		goto bail;
	arg = next_arg( &rsp );
	if (!arg || *arg != '*' || (arg = next_arg( &rsp )) == NULL) {
		error( "IMAP error: invalid greeting response\n" );
		goto bail;
	}
	preauth = 0;
	if (!strcmp( "PREAUTH", arg ))
		preauth = 1;
	else if (strcmp( "OK", arg ) != 0) {
		error( "IMAP error: unknown greeting response\n" );
		goto bail;
	}
	parse_response_code( ctx, 0, rsp );
	if (!ctx->caps && imap_exec( ctx, 0, "CAPABILITY" ) != RESP_OK)
		goto bail;

	if (!preauth) {
#ifdef HAVE_LIBSSL
		if (!srvc->use_imaps && (srvc->use_sslv2 || srvc->use_sslv3 || srvc->use_tlsv1)) {
			/* always try to select SSL support if available */
			if (CAP(STARTTLS)) {
				if (imap_exec( ctx, 0, "STARTTLS" ) != RESP_OK)
					goto bail;
				if (start_tls( ctx ))
					goto ssl_bail;
				use_ssl = 1;

				if (imap_exec( ctx, 0, "CAPABILITY" ) != RESP_OK)
					goto bail;
			} else {
				if (srvc->require_ssl) {
					error( "IMAP error: SSL support not available\n" );
					goto bail;
				} else
					warn( "IMAP warning: SSL support not available\n" );
			}
		}
#endif

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
			struct imap_cmd *cmd = new_imap_cmd();

			info( "Authenticating with CRAM-MD5\n" );
			cmd->param.cont = do_cram_auth;
			if (imap_exec( ctx, cmd, "AUTHENTICATE CRAM-MD5" ) != RESP_OK)
				goto bail;
		} else if (srvc->require_cram) {
			error( "IMAP error: CRAM-MD5 authentication is not supported by server\n" );
			goto bail;
		} else
#endif
		{
			if (CAP(NOLOGIN)) {
				error( "Skipping account %s, server forbids LOGIN\n", srvc->name );
				goto bail;
			}
#ifdef HAVE_LIBSSL
			if (!use_ssl)
#endif
				warn( "*** IMAP Warning *** Password is being sent in the clear\n" );
			if (imap_exec( ctx, 0, "LOGIN \"%s\" \"%s\"", srvc->user, srvc->pass ) != RESP_OK) {
				error( "IMAP error: LOGIN failed\n" );
				goto bail;
			}
		}
	} /* !preauth */

  final:
	ctx->prefix = "";
	if (*conf->path)
		ctx->prefix = conf->path;
	else if (cfg->use_namespace && CAP(NAMESPACE)) {
		/* get NAMESPACE info */
		if (!ctx->got_namespace) {
			if (imap_exec( ctx, 0, "NAMESPACE" ) != RESP_OK) {
				cb( 0, aux );
				return;
			}
			ctx->got_namespace = 1;
		}
		/* XXX for now assume personal namespace */
		if (is_list( ctx->ns_personal ) &&
		    is_list( ctx->ns_personal->child ) &&
		    is_atom( ctx->ns_personal->child->child ))
			ctx->prefix = ctx->ns_personal->child->child->val;
	}
	ctx->trashnc = 1;
	cb( &ctx->gen, aux );
	return;

#ifdef HAVE_LIBSSL
  ssl_bail:
	/* This avoids that we try to send LOGOUT to an unusable socket. */
	close( ctx->buf.sock.fd );
	ctx->buf.sock.fd = -1;
#endif
  bail:
	imap_cancel_store( &ctx->gen );
	cb( 0, aux );
}

static void
imap_prepare_paths( store_t *gctx )
{
	free_generic_messages( gctx->msgs );
	gctx->msgs = 0;
}

static void
imap_prepare_opts( store_t *gctx, int opts )
{
	gctx->opts = opts;
}

static int
imap_select( store_t *gctx, int minuid, int maxuid, int *excs, int nexcs,
             int (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd *cmd = new_imap_cmd();
	const char *prefix;
	int ret, i, j, bl;
	char buf[1000];


	if (!strcmp( gctx->name, "INBOX" )) {
//		ctx->currentnc = 0;
		prefix = "";
	} else {
//		ctx->currentnc = 1;	/* could use LIST results for that */
		prefix = ctx->prefix;
	}

	ctx->uidnext = -1;

	cmd->param.create = (gctx->opts & OPEN_CREATE) != 0;
	cmd->param.trycreate = 1;
	if ((ret = imap_exec_b( ctx, cmd, "SELECT \"%s%s\"", prefix, gctx->name )) != DRV_OK)
		goto bail;

	if (gctx->count) {
		ctx->msgapp = &gctx->msgs;
		sort_ints( excs, nexcs );
		for (i = 0; i < nexcs; ) {
			for (bl = 0; i < nexcs && bl < 960; i++) {
				if (bl)
					buf[bl++] = ',';
				bl += sprintf( buf + bl, "%d", excs[i] );
				j = i;
				for (; i + 1 < nexcs && excs[i + 1] == excs[i] + 1; i++);
				if (i != j)
					bl += sprintf( buf + bl, ":%d", excs[i] );
			}
			if ((ret = imap_exec_b( ctx, 0, "UID FETCH %s (UID%s%s)", buf,
			                        (gctx->opts & OPEN_FLAGS) ? " FLAGS" : "",
			                        (gctx->opts & OPEN_SIZE) ? " RFC822.SIZE" : "" )) != DRV_OK)
				goto bail;
		}
		if (maxuid == INT_MAX)
			maxuid = ctx->uidnext >= 0 ? ctx->uidnext - 1 : 1000000000;
		if (maxuid >= minuid &&
		    (ret = imap_exec_b( ctx, 0, "UID FETCH %d:%d (UID%s%s)", minuid, maxuid,
		                        (gctx->opts & OPEN_FLAGS) ? " FLAGS" : "",
		                        (gctx->opts & OPEN_SIZE) ? " RFC822.SIZE" : "" )) != DRV_OK)
			goto bail;
	}

	ret = DRV_OK;

  bail:
	free( excs );
	return cb( ret, aux );
}

static int
imap_fetch_msg( store_t *ctx, message_t *msg, msg_data_t *data,
                int (*cb)( int sts, void *aux ), void *aux )
{
	struct imap_cmd *cmd = new_imap_cmd();
	cmd->param.uid = msg->uid;
	cmd->param.aux = data;
	return cb( imap_exec_m( (imap_store_t *)ctx, cmd, "UID FETCH %d (%sBODY.PEEK[])",
	                        msg->uid, (msg->status & M_FLAGS) ? "" : "FLAGS " ), aux );
}

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
imap_flags_helper( imap_store_t *ctx, int uid, char what, int flags)
{
	char buf[256];

	buf[imap_make_flags( flags, buf )] = 0;
	if (!submit_imap_cmd( ctx, 0, "UID STORE %d %cFLAGS.SILENT %s", uid, what, buf ))
		return DRV_STORE_BAD;
	process_imap_replies( ctx );
	return DRV_OK;
}

static int
imap_set_flags( store_t *gctx, message_t *msg, int uid, int add, int del,
                int (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	int ret;

	if (msg) {
		uid = msg->uid;
		add &= ~msg->flags;
		del &= msg->flags;
		msg->flags |= add;
		msg->flags &= ~del;
	}
	if ((!add || (ret = imap_flags_helper( ctx, uid, '+', add )) == DRV_OK) &&
	    (!del || (ret = imap_flags_helper( ctx, uid, '-', del )) == DRV_OK))
		ret = DRV_OK;
	return cb( ret, aux );
}

static int
imap_close( store_t *ctx,
            int (*cb)( int sts, void *aux ), void *aux )
{
	return cb( imap_exec_b( (imap_store_t *)ctx, 0, "CLOSE" ), aux );
}

static int
imap_trash_msg( store_t *gctx, message_t *msg,
                int (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd *cmd = new_imap_cmd();
	cmd->param.create = 1;
	return cb( imap_exec_m( ctx, cmd, "UID COPY %d \"%s%s\"",
	                        msg->uid, ctx->prefix, gctx->conf->trash ), aux );
}

static int
imap_store_msg( store_t *gctx, msg_data_t *data, int to_trash,
                int (*cb)( int sts, int uid, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd *cmd = new_imap_cmd();
	const char *prefix, *box;
	int ret, d, uid;
	char flagstr[128];

	d = 0;
	if (data->flags) {
		d = imap_make_flags( data->flags, flagstr );
		flagstr[d++] = ' ';
	}
	flagstr[d] = 0;

	cmd->param.data_len = data->len;
	cmd->param.data = data->data;
	cmd->param.aux = &uid;
	uid = -2;

	if (to_trash) {
		box = gctx->conf->trash;
		prefix = ctx->prefix;
		cmd->param.create = 1;
		if (ctx->trashnc)
			ctx->caps = ctx->rcaps & ~(1 << LITERALPLUS);
	} else {
		box = gctx->name;
		prefix = !strcmp( box, "INBOX" ) ? "" : ctx->prefix;
		cmd->param.create = (gctx->opts & OPEN_CREATE) != 0;
		/*if (ctx->currentnc)
			ctx->caps = ctx->rcaps & ~(1 << LITERALPLUS);*/
	}
	ret = imap_exec_m( ctx, cmd, "APPEND \"%s%s\" %s", prefix, box, flagstr );
	ctx->caps = ctx->rcaps;
	if (ret != DRV_OK)
		return cb( ret, -1, aux );
	if (to_trash)
		ctx->trashnc = 0;
	else {
		/*ctx->currentnc = 0;*/
	}

	return cb( DRV_OK, uid, aux );
}

static int
imap_find_msg( store_t *gctx, const char *tuid,
               int (*cb)( int sts, int uid, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd *cmd = new_imap_cmd();
	int ret, uid;

	cmd->param.uid = -1; /* we're looking for a UID */
	cmd->param.aux = &uid;
	uid = -1; /* in case we get no SEARCH response at all */
	if ((ret = imap_exec_m( ctx, cmd, "UID SEARCH HEADER X-TUID %." stringify(TUIDL) "s", tuid )) != DRV_OK)
		return cb( ret, -1, aux );
	else
		return cb( uid <= 0 ? DRV_MSG_BAD : DRV_OK, uid, aux );
}

static void
imap_list( store_t *gctx,
           void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	int ret;

	if ((ret = imap_exec_b( ctx, 0, "LIST \"\" \"%s%%\"", ctx->prefix )) == DRV_OK)
		gctx->listed = 1;
	cb( ret, aux );
}

static void
imap_cancel( store_t *gctx,
             void (*cb)( int sts, void *aux ), void *aux )
{
	(void)gctx;
	cb( DRV_OK, aux );
}

static void
imap_commit( store_t *gctx )
{
	(void)gctx;
}

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
	imap_prepare_paths,
	imap_prepare_opts,
	imap_select,
	imap_fetch_msg,
	imap_store_msg,
	imap_find_msg,
	imap_set_flags,
	imap_trash_msg,
	imap_close,
	imap_cancel,
	imap_commit,
};
