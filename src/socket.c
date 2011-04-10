/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2008,2010,2011 Oswald Buddenhagen <ossi@users.sf.net>
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
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

enum {
	SCK_CONNECTING,
#ifdef HAVE_LIBSSL
	SCK_STARTTLS,
#endif
	SCK_READY
};

static void
socket_fail( conn_t *conn )
{
	conn->bad_callback( conn->callback_aux );
}

#ifdef HAVE_LIBSSL
static int
ssl_return( const char *func, conn_t *conn, int ret )
{
	int err;

	switch ((err = SSL_get_error( conn->ssl, ret ))) {
	case SSL_ERROR_NONE:
		return ret;
	case SSL_ERROR_WANT_WRITE:
		conf_fd( conn->fd, POLLIN, POLLOUT );
		/* fallthrough */
	case SSL_ERROR_WANT_READ:
		return 0;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		if (!(err = ERR_get_error())) {
			if (ret == 0)
				error( "Socket error: secure %s %s: unexpected EOF\n", func, conn->name );
			else
				sys_error( "Socket error: secure %s %s", func, conn->name );
		} else {
			error( "Socket error: secure %s %s: %s\n", func, conn->name, ERR_error_string( err, 0 ) );
		}
		break;
	default:
		error( "Socket error: secure %s %s: unhandled SSL error %d\n", func, conn->name, err );
		break;
	}
	if (conn->state == SCK_STARTTLS)
		conn->callbacks.starttls( 0, conn->callback_aux );
	else
		socket_fail( conn );
	return -1;
}

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
verify_cert( const server_conf_t *conf, conn_t *sock )
{
	server_conf_t *mconf = (server_conf_t *)conf;
	SSL *ssl = sock->ssl;
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

	while (conf->cert_file) { /* while() instead of if() so break works */
		if (X509_cmp_current_time( X509_get_notBefore( cert )) >= 0) {
			error( "Server certificate is not yet valid\n" );
			break;
		}
		if (X509_cmp_current_time( X509_get_notAfter( cert )) <= 0) {
			error( "Server certificate has expired\n" );
			break;
		}
		if (!X509_digest( cert, EVP_sha1(), md, &n )) {
			error( "*** Unable to calculate digest\n" );
			break;
		}
		if (!(fp = fopen( conf->cert_file, "rt" ))) {
			sys_error( "Unable to load CertificateFile '%s'", conf->cert_file );
			return -1;
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

	if (!mconf->cert_store) {
		if (!(mconf->cert_store = X509_STORE_new())) {
			error( "Error creating certificate store\n" );
			return -1;
		}
		if (!X509_STORE_set_default_paths( mconf->cert_store ))
			warn( "Error while loading default certificate files: %s\n",
			      ERR_error_string( ERR_get_error(), 0 ) );
		if (!conf->cert_file) {
			info( "Note: CertificateFile not defined\n" );
		} else if (!X509_STORE_load_locations( mconf->cert_store, conf->cert_file, 0 )) {
			error( "Error while loading certificate file '%s': %s\n",
			       conf->cert_file, ERR_error_string( ERR_get_error(), 0 ) );
			return -1;
		}
	}

	X509_STORE_CTX_init( &xsc, mconf->cert_store, cert, 0 );
	err = X509_verify_cert( &xsc ) > 0 ? 0 : X509_STORE_CTX_get_error( &xsc );
	X509_STORE_CTX_cleanup( &xsc );
	if (!err)
		return 0;
	error( "Error, cannot verify certificate: %s (%d)\n",
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
init_ssl_ctx( const server_conf_t *conf )
{
	server_conf_t *mconf = (server_conf_t *)conf;
	const SSL_METHOD *method;
	int options = 0;

	if (conf->use_tlsv1 && !conf->use_sslv2 && !conf->use_sslv3)
		method = TLSv1_client_method();
	else
		method = SSLv23_client_method();
	mconf->SSLContext = SSL_CTX_new( method );

	if (!conf->use_sslv2)
		options |= SSL_OP_NO_SSLv2;
	if (!conf->use_sslv3)
		options |= SSL_OP_NO_SSLv3;
	if (!conf->use_tlsv1)
		options |= SSL_OP_NO_TLSv1;

	SSL_CTX_set_options( mconf->SSLContext, options );

	/* we check the result of the verification after SSL_connect() */
	SSL_CTX_set_verify( mconf->SSLContext, SSL_VERIFY_NONE, 0 );
	return 0;
}

static void start_tls_p2( conn_t * );
static void start_tls_p3( conn_t *, int );

void
socket_start_tls( conn_t *conn, void (*cb)( int ok, void *aux ) )
{
	static int ssl_inited;

	conn->callbacks.starttls = cb;

	if (!ssl_inited) {
		SSL_library_init();
		SSL_load_error_strings();
		ssl_inited = 1;
	}

	if (!conn->conf->SSLContext && init_ssl_ctx( conn->conf )) {
		start_tls_p3( conn, 0 );
		return;
	}

	conn->ssl = SSL_new( ((server_conf_t *)conn->conf)->SSLContext );
	SSL_set_fd( conn->ssl, conn->fd );
	SSL_set_mode( conn->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER );
	start_tls_p2( conn );
}

static void
start_tls_p2( conn_t *conn )
{
	switch (ssl_return( "connect to", conn, SSL_connect( conn->ssl ) )) {
	case -1:
		start_tls_p3( conn, 0 );
		break;
	case 0:
		break;
	default:
		/* verify the server certificate */
		if (verify_cert( conn->conf, conn )) {
			start_tls_p3( conn, 0 );
		} else {
			info( "Connection is now encrypted\n" );
			start_tls_p3( conn, 1 );
		}
		break;
	}
}

static void start_tls_p3( conn_t *conn, int ok )
{
	conn->state = SCK_READY;
	conn->callbacks.starttls( ok, conn->callback_aux );
}

#endif /* HAVE_LIBSSL */

static void socket_fd_cb( int, void * );

static void socket_connected2( conn_t * );
static void socket_connect_bail( conn_t * );

static void
socket_close_internal( conn_t *sock )
{
	del_fd( sock->fd );
	close( sock->fd );
	sock->fd = -1;
}

void
socket_connect( conn_t *sock, void (*cb)( int ok, void *aux ) )
{
	const server_conf_t *conf = sock->conf;
	struct hostent *he;
	struct sockaddr_in addr;
	int s, a[2];

	sock->callbacks.connect = cb;

	/* open connection to IMAP server */
	if (conf->tunnel) {
		nfasprintf( &sock->name, "tunnel '%s'", conf->tunnel );
		infon( "Starting %s... ", sock->name );

		if (socketpair( PF_UNIX, SOCK_STREAM, 0, a )) {
			perror( "socketpair" );
			exit( 1 );
		}

		if (fork() == 0) {
			if (dup2( a[0], 0 ) == -1 || dup2( a[0], 1 ) == -1)
				_exit( 127 );
			close( a[0] );
			close( a[1] );
			execl( "/bin/sh", "sh", "-c", conf->tunnel, (char *)0 );
			_exit( 127 );
		}

		close( a[0] );
		sock->fd = a[1];

		fcntl( a[1], F_SETFL, O_NONBLOCK );
		add_fd( a[1], socket_fd_cb, sock );

	} else {
		memset( &addr, 0, sizeof(addr) );
		addr.sin_port = conf->port ? htons( conf->port ) :
#ifdef HAVE_LIBSSL
		                conf->use_imaps ? htons( 993 ) :
#endif
		                htons( 143 );
		addr.sin_family = AF_INET;

		infon( "Resolving %s... ", conf->host );
		he = gethostbyname( conf->host );
		if (!he) {
			error( "IMAP error: Cannot resolve server '%s'\n", conf->host );
			goto bail;
		}
		info( "ok\n" );

		addr.sin_addr.s_addr = *((int *)he->h_addr_list[0]);

		s = socket( PF_INET, SOCK_STREAM, 0 );
		if (s < 0) {
			perror( "socket" );
			exit( 1 );
		}
		sock->fd = s;
		fcntl( s, F_SETFL, O_NONBLOCK );
		add_fd( s, socket_fd_cb, sock );

		nfasprintf( &sock->name, "%s (%s:%hu)",
		            conf->host, inet_ntoa( addr.sin_addr ), ntohs( addr.sin_port ) );
		infon( "Connecting to %s... ", sock->name );
		if (connect( s, (struct sockaddr *)&addr, sizeof(addr) )) {
			if (errno != EINPROGRESS) {
				sys_error( "Cannot connect to %s", sock->name );
				socket_close_internal( sock );
				goto bail;
			}
			conf_fd( s, 0, POLLOUT );
			sock->state = SCK_CONNECTING;
			info( "\n" );
			return;
		}

	}
	info( "ok\n" );
	socket_connected2( sock );
	return;

  bail:
	socket_connect_bail( sock );
}

static void
socket_connected( conn_t *conn )
{
	int soerr;
	socklen_t selen = sizeof(soerr);

	if (getsockopt( conn->fd, SOL_SOCKET, SO_ERROR, &soerr, &selen )) {
		perror( "getsockopt" );
		exit( 1 );
	}
	if (soerr) {
		errno = soerr;
		sys_error( "Cannot connect to %s", conn->name );
		socket_close_internal( conn );
		socket_connect_bail( conn );
		return;
	}
	socket_connected2( conn );
}

static void
socket_connected2( conn_t *conn )
{
	conf_fd( conn->fd, 0, POLLIN );
	conn->state = SCK_READY;
	conn->callbacks.connect( 1, conn->callback_aux );
}

static void
socket_connect_bail( conn_t *conn )
{
	free( conn->name );
	conn->name = 0;
	conn->callbacks.connect( 0, conn->callback_aux );
}

static void dispose_chunk( conn_t *conn );

void
socket_close( conn_t *sock )
{
	if (sock->fd >= 0)
		socket_close_internal( sock );
	free( sock->name );
	sock->name = 0;
#ifdef HAVE_LIBSSL
	if (sock->ssl) {
		SSL_free( sock->ssl );
		sock->ssl = 0;
	}
#endif
	while (sock->write_buf)
		dispose_chunk( sock );
}

static void
socket_fill( conn_t *sock )
{
	char *buf;
	int n = sock->offset + sock->bytes;
	int len = sizeof(sock->buf) - n;
	if (!len) {
		error( "Socket error: receive buffer full. Probably protocol error.\n" );
		socket_fail( sock );
		return;
	}
	assert( sock->fd >= 0 );
	buf = sock->buf + n;
#ifdef HAVE_LIBSSL
	if (sock->ssl) {
		if ((n = ssl_return( "read from", sock, SSL_read( sock->ssl, buf, len ) )) <= 0)
			return;
		if (n == len && SSL_pending( sock->ssl ))
			fake_fd( sock->fd, POLLIN );
	} else
#endif
	{
		if ((n = read( sock->fd, buf, len )) < 0) {
			sys_error( "Socket error: read from %s", sock->name );
			socket_fail( sock );
			return;
		} else if (!n) {
			error( "Socket error: read from %s: unexpected EOF\n", sock->name );
			socket_fail( sock );
			return;
		}
	}
	sock->bytes += n;
	sock->read_callback( sock->callback_aux );
}

int
socket_read( conn_t *conn, char *buf, int len )
{
	int n = conn->bytes;
	if (n > len)
		n = len;
	memcpy( buf, conn->buf + conn->offset, n );
	if (!(conn->bytes -= n))
		conn->offset = 0;
	else
		conn->offset += n;
	return n;
}

char *
socket_read_line( conn_t *b )
{
	char *p, *s;
	int n;

	s = b->buf + b->offset;
	p = memchr( s + b->scanoff, '\n', b->bytes - b->scanoff );
	if (!p) {
		b->scanoff = b->bytes;
		if (b->offset + b->bytes == sizeof(b->buf)) {
			memmove( b->buf, b->buf + b->offset, b->bytes );
			b->offset = 0;
		}
		return 0;
	}
	n = p + 1 - s;
	b->offset += n;
	b->bytes -= n;
	b->scanoff = 0;
	if (p != s && p[-1] == '\r')
		p--;
	*p = 0;
	if (DFlags & VERBOSE)
		puts( s );
	return s;
}

static int
do_write( conn_t *sock, char *buf, int len )
{
	int n;

	assert( sock->fd >= 0 );
#ifdef HAVE_LIBSSL
	if (sock->ssl)
		return ssl_return( "write to", sock, SSL_write( sock->ssl, buf, len ) );
#endif
	n = write( sock->fd, buf, len );
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			sys_error( "Socket error: write to %s", sock->name );
			socket_fail( sock );
		} else {
			n = 0;
			conf_fd( sock->fd, POLLIN, POLLOUT );
		}
	} else if (n != len) {
		conf_fd( sock->fd, POLLIN, POLLOUT );
	}
	return n;
}

static void
dispose_chunk( conn_t *conn )
{
	buff_chunk_t *bc = conn->write_buf;
	if (!(conn->write_buf = bc->next))
		conn->write_buf_append = &conn->write_buf;
	if (bc->data != bc->buf)
		free( bc->data );
	free( bc );
}

static int
do_queued_write( conn_t *conn )
{
	buff_chunk_t *bc;

	if (!conn->write_buf)
		return 0;

	while ((bc = conn->write_buf)) {
		int n, len = bc->len - conn->write_offset;
		if ((n = do_write( conn, bc->data + conn->write_offset, len )) < 0)
			return -1;
		if (n != len) {
			conn->write_offset += n;
			return 0;
		}
		conn->write_offset = 0;
		dispose_chunk( conn );
	}
#ifdef HAVE_LIBSSL
	if (conn->ssl && SSL_pending( conn->ssl ))
		fake_fd( conn->fd, POLLIN );
#endif
	return conn->write_callback( conn->callback_aux );
}

static void
do_append( conn_t *conn, char *buf, int len, ownership_t takeOwn )
{
	buff_chunk_t *bc;

	if (takeOwn == GiveOwn) {
		bc = nfmalloc( offsetof(buff_chunk_t, buf) );
		bc->data = buf;
	} else {
		bc = nfmalloc( offsetof(buff_chunk_t, buf) + len );
		bc->data = bc->buf;
		memcpy( bc->data, buf, len );
	}
	bc->len = len;
	bc->next = 0;
	*conn->write_buf_append = bc;
	conn->write_buf_append = &bc->next;
}

int
socket_write( conn_t *conn, char *buf, int len, ownership_t takeOwn )
{
	if (conn->write_buf) {
		do_append( conn, buf, len, takeOwn );
		return len;
	} else {
		int n = do_write( conn, buf, len );
		if (n != len && n >= 0) {
			conn->write_offset = n;
			do_append( conn, buf, len, takeOwn );
		} else if (takeOwn) {
			free( buf );
		}
		return n;
	}
}

static void
socket_fd_cb( int events, void *aux )
{
	conn_t *conn = (conn_t *)aux;

	if (events & POLLERR) {
		error( "Unidentified socket error from %s.\n", conn->name );
		socket_fail( conn );
		return;
	}

	if (conn->state == SCK_CONNECTING) {
		socket_connected( conn );
		return;
	}

	if (events & POLLOUT)
		conf_fd( conn->fd, POLLIN, 0 );

#ifdef HAVE_LIBSSL
	if (conn->state == SCK_STARTTLS) {
		start_tls_p2( conn );
		return;
	}
	if (conn->ssl) {
		if (do_queued_write( conn ) < 0)
			return;
		socket_fill( conn );
		return;
	}
#endif

	if ((events & POLLOUT) && do_queued_write( conn ) < 0)
		return;
	if (events & POLLIN)
		socket_fill( conn );
}

#ifdef HAVE_LIBSSL
/* this isn't strictly socket code, but let's have all OpenSSL use in one file. */

#define ENCODED_SIZE(n) (4*((n+2)/3))

static char
hexchar( unsigned int b )
{
	if (b < 10)
		return '0' + b;
	return 'a' + (b - 10);
}

void
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
#endif
