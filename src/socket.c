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
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

static void
socket_fail( conn_t *conn )
{
	conn->bad_callback( conn->callback_aux );
}

static void
socket_perror( const char *func, conn_t *sock, int ret )
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
			break;
		default:
			error( "SSL_%s: unhandled SSL error %d\n", func, err );
			break;
		}
	} else
#endif
	if (ret < 0)
		perror( func );
	else
		error( "%s: unexpected EOF\n", func );
	socket_fail( sock );
}

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
		if (!(fp = fopen( conf->cert_file, "rt" ))) {
			error( "Unable to load CertificateFile '%s': %s\n",
			       conf->cert_file, strerror( errno ) );
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

int
socket_start_tls( const server_conf_t *conf, conn_t *sock )
{
	int ret;
	static int ssl_inited;

	if (!ssl_inited) {
		SSL_library_init();
		SSL_load_error_strings();
		ssl_inited = 1;
	}

	if (!conf->SSLContext && init_ssl_ctx( conf ))
		return 1;

	sock->ssl = SSL_new( ((server_conf_t *)conf)->SSLContext );
	SSL_set_fd( sock->ssl, sock->fd );
	if ((ret = SSL_connect( sock->ssl )) <= 0) {
		socket_perror( "connect", sock, ret );
		return 1;
	}

	/* verify the server certificate */
	if (verify_cert( conf, sock ))
		return 1;

	info( "Connection is now encrypted\n" );
	return 0;
}

#endif /* HAVE_LIBSSL */

int
socket_connect( const server_conf_t *conf, conn_t *sock )
{
	struct hostent *he;
	struct sockaddr_in addr;
	int s, a[2];

	/* open connection to IMAP server */
	if (conf->tunnel) {
		infon( "Starting tunnel '%s'... ", conf->tunnel );

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
			return -1;
		}
		info( "ok\n" );

		addr.sin_addr.s_addr = *((int *)he->h_addr_list[0]);

		s = socket( PF_INET, SOCK_STREAM, 0 );
		if (s < 0) {
			perror( "socket" );
			exit( 1 );
		}

		infon( "Connecting to %s:%hu... ", inet_ntoa( addr.sin_addr ), ntohs( addr.sin_port ) );
		if (connect( s, (struct sockaddr *)&addr, sizeof(addr) )) {
			close( s );
			perror( "connect" );
			return -1;
		}

		sock->fd = s;
	}
	info( "ok\n" );
	return 0;
}

void
socket_close( conn_t *sock )
{
	if (sock->fd >= 0) {
		close( sock->fd );
		sock->fd = -1;
	}
#ifdef HAVE_LIBSSL
	if (sock->ssl) {
		SSL_free( sock->ssl );
		sock->ssl = 0;
	}
#endif
}

int
socket_fill( conn_t *sock )
{
	char *buf;
	int n = sock->offset + sock->bytes;
	int len = sizeof(sock->buf) - n;
	if (!len) {
		error( "Socket error: receive buffer full. Probably protocol error.\n" );
		socket_fail( sock );
		return -1;
	}
	assert( sock->fd >= 0 );
	buf = sock->buf + n;
	n =
#ifdef HAVE_LIBSSL
		sock->ssl ? SSL_read( sock->ssl, buf, len ) :
#endif
		read( sock->fd, buf, len );
	if (n <= 0) {
		socket_perror( "read", sock, n );
		close( sock->fd );
		sock->fd = -1;
		return -1;
	} else {
		sock->bytes += n;
		return 0;
	}
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

int
socket_write( conn_t *sock, char *buf, int len, ownership_t takeOwn )
{
	int n;

	assert( sock->fd >= 0 );
	n =
#ifdef HAVE_LIBSSL
		sock->ssl ? SSL_write( sock->ssl, buf, len ) :
#endif
		write( sock->fd, buf, len );
	if (takeOwn == GiveOwn)
		free( buf );
	if (n != len) {
		socket_perror( "write", sock, n );
		close( sock->fd );
		sock->fd = -1;
		return -1;
	}
	return 0;
}

int
socket_pending( conn_t *sock )
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
