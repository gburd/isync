/*
 * isync - mbsync wrapper: IMAP4 to maildir mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>
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
 */

#include "isync.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <ctype.h>

void
sys_error( const char *msg, ... )
{
	va_list va;
	char buf[1024];

	va_start( va, msg );
	if ((unsigned)vsnprintf( buf, sizeof(buf), msg, va ) >= sizeof(buf))
		oob();
	va_end( va );
	perror( buf );
}

char *
next_arg( char **s )
{
	char *ret;

	if (!s || !*s)
		return 0;
	while (isspace( (unsigned char) **s ))
		(*s)++;
	if (!**s) {
		*s = 0;
		return 0;
	}
	if (**s == '"') {
		++*s;
		ret = *s;
		*s = strchr( *s, '"' );
	} else {
		ret = *s;
		while (**s && !isspace( (unsigned char) **s ))
			(*s)++;
	}
	if (*s) {
		if (**s)
			*(*s)++ = 0;
		if (!**s)
			*s = 0;
	}
	return ret;
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
