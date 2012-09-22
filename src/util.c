/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2011,2012 Oswald Buddenhagen <ossi@users.sf.net>
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, mbsync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

#include "isync.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>

int DFlags;
static int need_nl;

void
flushn( void )
{
	if (need_nl) {
		putchar( '\n' );
		fflush( stdout );
		need_nl = 0;
	}
}

static void
printn( const char *msg, va_list va )
{
	if (*msg == '\v')
		msg++;
	else
		flushn();
	vprintf( msg, va );
	fflush( stdout );
}

void
debug( const char *msg, ... )
{
	va_list va;

	if (DFlags & DEBUG) {
		va_start( va, msg );
		vprintf( msg, va );
		va_end( va );
		fflush( stdout );
		need_nl = 0;
	}
}

void
debugn( const char *msg, ... )
{
	va_list va;

	if (DFlags & DEBUG) {
		va_start( va, msg );
		vprintf( msg, va );
		va_end( va );
		fflush( stdout );
		need_nl = 1;
	}
}

void
info( const char *msg, ... )
{
	va_list va;

	if (!(DFlags & QUIET)) {
		va_start( va, msg );
		printn( msg, va );
		va_end( va );
		need_nl = 0;
	}
}

void
infon( const char *msg, ... )
{
	va_list va;

	if (!(DFlags & QUIET)) {
		va_start( va, msg );
		printn( msg, va );
		va_end( va );
		need_nl = 1;
	}
}

void
warn( const char *msg, ... )
{
	va_list va;

	if (!(DFlags & VERYQUIET)) {
		flushn();
		va_start( va, msg );
		vfprintf( stderr, msg, va );
		va_end( va );
	}
}

void
error( const char *msg, ... )
{
	va_list va;

	flushn();
	va_start( va, msg );
	vfprintf( stderr, msg, va );
	va_end( va );
}

void
sys_error( const char *msg, ... )
{
	va_list va;
	char buf[1024];

	flushn();
	va_start( va, msg );
	if ((unsigned)vsnprintf( buf, sizeof(buf), msg, va ) >= sizeof(buf))
		oob();
	va_end( va );
	perror( buf );
}

void
add_string_list( string_list_t **list, const char *str )
{
	string_list_t *elem;
	int len;

	len = strlen( str );
	elem = nfmalloc( sizeof(*elem) + len );
	elem->next = *list;
	*list = elem;
	memcpy( elem->string, str, len + 1 );
}

void
free_string_list( string_list_t *list )
{
	string_list_t *tlist;

	for (; list; list = tlist) {
		tlist = list->next;
		free( list );
	}
}

void
free_generic_messages( message_t *msgs )
{
	message_t *tmsg;

	for (; msgs; msgs = tmsg) {
		tmsg = msgs->next;
		free( msgs );
	}
}

#ifndef HAVE_VASPRINTF
static int
vasprintf( char **strp, const char *fmt, va_list ap )
{
	int len;
	char tmp[1024];

	if ((len = vsnprintf( tmp, sizeof(tmp), fmt, ap )) < 0 || !(*strp = malloc( len + 1 )))
		return -1;
	if (len >= (int)sizeof(tmp))
		vsprintf( *strp, fmt, ap );
	else
		memcpy( *strp, tmp, len + 1 );
	return len;
}
#endif

#ifndef HAVE_MEMRCHR
void *
memrchr( const void *s, int c, size_t n )
{
	u_char *b = (u_char *)s, *e = b + n;

	while (--e >= b)
		if (*e == c)
			return (void *)e;
	return 0;
}
#endif

void
oob( void )
{
	fputs( "Fatal: buffer too small. Please report a bug.\n", stderr );
	abort();
}

int
nfsnprintf( char *buf, int blen, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	if (blen <= 0 || (unsigned)(ret = vsnprintf( buf, blen, fmt, va )) >= (unsigned)blen)
		oob();
	va_end( va );
	return ret;
}

static void ATTR_NORETURN
oom( void )
{
	fputs( "Fatal: Out of memory\n", stderr );
	abort();
}

void *
nfmalloc( size_t sz )
{
	void *ret;

	if (!(ret = malloc( sz )))
		oom();
	return ret;
}

void *
nfcalloc( size_t sz )
{
	void *ret;

	if (!(ret = calloc( sz, 1 )))
		oom();
	return ret;
}

void *
nfrealloc( void *mem, size_t sz )
{
	char *ret;

	if (!(ret = realloc( mem, sz )) && sz)
		oom();
	return ret;
}

char *
nfstrdup( const char *str )
{
	char *ret;

	if (!(ret = strdup( str )))
		oom();
	return ret;
}

int
nfvasprintf( char **str, const char *fmt, va_list va )
{
	int ret = vasprintf( str, fmt, va );
	if (ret < 0)
		oom();
	return ret;
}

int
nfasprintf( char **str, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	ret = nfvasprintf( str, fmt, va );
	va_end( va );
	return ret;
}

/*
static struct passwd *
cur_user( void )
{
	char *p;
	struct passwd *pw;
	uid_t uid;

	uid = getuid();
	if ((!(p = getenv("LOGNAME")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    (!(p = getenv("USER")) || !(pw = getpwnam( p )) || pw->pw_uid != uid) &&
	    !(pw = getpwuid( uid )))
	{
		fputs ("Cannot determinate current user\n", stderr);
		return 0;
	}
	return pw;
}
*/

static char *
my_strndup( const char *s, size_t nchars )
{
	char *r = nfmalloc( nchars + 1 );
	memcpy( r, s, nchars );
	r[nchars] = 0;
	return r;
}

char *
expand_strdup( const char *s )
{
	struct passwd *pw;
	const char *p, *q;
	char *r;

	if (*s == '~') {
		s++;
		if (!*s) {
			p = 0;
			q = Home;
		} else if (*s == '/') {
			p = s;
			q = Home;
		} else {
			if ((p = strchr( s, '/' ))) {
				r = my_strndup( s, (int)(p - s) );
				pw = getpwnam( r );
				free( r );
			} else
				pw = getpwnam( s );
			if (!pw)
				return 0;
			q = pw->pw_dir;
		}
		nfasprintf( &r, "%s%s", q, p ? p : "" );
		return r;
	} else
		return nfstrdup( s );
}

/* Return value: 0 = ok, -1 = out found in arg, -2 = in found in arg but no out specified */
int
map_name( char *arg, char in, char out )
{
	int l, k;

	if (!in || in == out)
		return 0;
	for (l = 0; arg[l]; l++)
		if (arg[l] == in) {
			if (!out)
				return -2;
			arg[l] = out;
		} else if (arg[l] == out) {
			/* restore original name for printing error message */
			for (k = 0; k < l; k++)
				if (arg[k] == out)
					arg[k] = in;
			return -1;
		}
	return 0;
}

static int
compare_ints( const void *l, const void *r )
{
	return *(int *)l - *(int *)r;
}

void
sort_ints( int *arr, int len )
{
	qsort( arr, len, sizeof(int), compare_ints );
}


static struct {
	unsigned char i, j, s[256];
} rs;

void
arc4_init( void )
{
	int i, fd;
	unsigned char j, si, dat[128];

	if ((fd = open( "/dev/urandom", O_RDONLY )) < 0 && (fd = open( "/dev/random", O_RDONLY )) < 0) {
		error( "Fatal: no random number source available.\n" );
		exit( 3 );
	}
	if (read( fd, dat, 128 ) != 128) {
		error( "Fatal: cannot read random number source.\n" );
		exit( 3 );
	}
	close( fd );

	for (i = 0; i < 256; i++)
		rs.s[i] = i;
	for (i = j = 0; i < 256; i++) {
		si = rs.s[i];
		j += si + dat[i & 127];
		rs.s[i] = rs.s[j];
		rs.s[j] = si;
	}
	rs.i = rs.j = 0;

	for (i = 0; i < 256; i++)
		arc4_getbyte();
}

unsigned char
arc4_getbyte( void )
{
	unsigned char si, sj;

	rs.i++;
	si = rs.s[rs.i];
	rs.j += si;
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;
	return rs.s[(si + sj) & 0xff];
}

static const unsigned char prime_deltas[] = {
    0,  0,  1,  3,  1,  5,  3,  3,  1,  9,  7,  5,  3,  9, 25,  3,
    1, 21,  3, 21,  7, 15,  9,  5,  3, 29, 15,  0,  0,  0,  0,  0
};

int
bucketsForSize( int size )
{
	int base = 4, bits = 2;

	for (;;) {
		int prime = base + prime_deltas[bits];
		if (prime >= size)
			return prime;
		base <<= 1;
		bits++;
	}
}

#ifdef HAVE_SYS_POLL_H
static struct pollfd *pollfds;
#else
# ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h>
# endif
# define pollfds fdparms
#endif
static struct {
	void (*cb)( int what, void *aux );
	void *aux;
#ifndef HAVE_SYS_POLL_H
	int fd, events;
#endif
	int faked;
} *fdparms;
static int npolls, rpolls, changed;

static int
find_fd( int fd )
{
	int n;

	for (n = 0; n < npolls; n++)
		if (pollfds[n].fd == fd)
			return n;
	return -1;
}

void
add_fd( int fd, void (*cb)( int events, void *aux ), void *aux )
{
	int n;

	assert( find_fd( fd ) < 0 );
	n = npolls++;
	if (rpolls < npolls) {
		rpolls = npolls;
#ifdef HAVE_SYS_POLL_H
		pollfds = nfrealloc(pollfds, npolls * sizeof(*pollfds));
#endif
		fdparms = nfrealloc(fdparms, npolls * sizeof(*fdparms));
	}
	pollfds[n].fd = fd;
	pollfds[n].events = 0; /* POLLERR & POLLHUP implicit */
	fdparms[n].faked = 0;
	fdparms[n].cb = cb;
	fdparms[n].aux = aux;
	changed = 1;
}

void
conf_fd( int fd, int and_events, int or_events )
{
	int n = find_fd( fd );
	assert( n >= 0 );
	pollfds[n].events = (pollfds[n].events & and_events) | or_events;
}

void
fake_fd( int fd, int events )
{
	int n = find_fd( fd );
	assert( n >= 0 );
	fdparms[n].faked |= events;
}

void
del_fd( int fd )
{
	int n = find_fd( fd );
	assert( n >= 0 );
	npolls--;
#ifdef HAVE_SYS_POLL_H
	memmove(pollfds + n, pollfds + n + 1, (npolls - n) * sizeof(*pollfds));
#endif
	memmove(fdparms + n, fdparms + n + 1, (npolls - n) * sizeof(*fdparms));
	changed = 1;
}

#define shifted_bit(in, from, to) \
	(((unsigned)(in) & from) \
		/ (from > to ? from / to : 1) \
		* (to > from ? to / from : 1))

static void
event_wait( void )
{
	int m, n;

#ifdef HAVE_SYS_POLL_H
	int timeout = -1;
	for (n = 0; n < npolls; n++)
		if (fdparms[n].faked) {
			timeout = 0;
			break;
		}
	if (poll( pollfds, npolls, timeout ) < 0) {
		perror( "poll() failed in event loop" );
		abort();
	}
	for (n = 0; n < npolls; n++)
		if ((m = pollfds[n].revents | fdparms[n].faked)) {
			assert( !(m & POLLNVAL) );
			fdparms[n].faked = 0;
			fdparms[n].cb( m | shifted_bit( m, POLLHUP, POLLIN ), fdparms[n].aux );
			if (changed) {
				changed = 0;
				break;
			}
		}
#else
	struct timeval *timeout = 0;
	static struct timeval null_tv;
	fd_set rfds, wfds, efds;
	int fd;

	FD_ZERO( &rfds );
	FD_ZERO( &wfds );
	FD_ZERO( &efds );
	m = -1;
	for (n = 0; n < npolls; n++) {
		if (fdparms[n].faked)
			timeout = &null_tv;
		fd = fdparms[n].fd;
		if (fdparms[n].events & POLLIN)
			FD_SET( fd, &rfds );
		if (fdparms[n].events & POLLOUT)
			FD_SET( fd, &wfds );
		FD_SET( fd, &efds );
		if (fd > m)
			m = fd;
	}
	if (select( m + 1, &rfds, &wfds, &efds, timeout ) < 0) {
		perror( "select() failed in event loop" );
		abort();
	}
	for (n = 0; n < npolls; n++) {
		fd = fdparms[n].fd;
		m = fdparms[n].faked;
		if (FD_ISSET( fd, &rfds ))
			m |= POLLIN;
		if (FD_ISSET( fd, &wfds ))
			m |= POLLOUT;
		if (FD_ISSET( fd, &efds ))
			m |= POLLERR;
		if (m) {
			fdparms[n].faked = 0;
			fdparms[n].cb( m, fdparms[n].aux );
			if (changed) {
				changed = 0;
				break;
			}
		}
	}
#endif
}

void
main_loop( void )
{
	while (npolls)
		event_wait();
}
