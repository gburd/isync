/*
 * mdconvert - Maildir UID scheme converter
 * Copyright (C) 2004 Oswald Buddenhagen <ossi@users.sf.net>
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
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <db.h>

#define EXE "mdconvert"

static int
nfsnprintf( char *buf, int blen, const char *fmt, ... )
{
	int ret;
	va_list va;

	va_start( va, fmt );
	if (blen <= 0 || (unsigned)(ret = vsnprintf( buf, blen, fmt, va )) >= (unsigned)blen) {
		fputs( "Fatal: buffer too small. Please report a bug.\n", stderr );
		abort();
	}
	va_end( va );
	return ret;
}

static const char *subdirs[] = { "cur", "new" };
static struct flock lck;
static DBT key, value;

static int
convert( const char *box, int altmap )
{
	DB *db;
	DIR *d;
	struct dirent *e;
	const char *u, *ru;
	char *p, *s, *dpath, *spath, *dbpath;
	int i, n, ret, sfd, dfd, bl, ml, uv[2], uid;
	struct stat st;
	char buf[_POSIX_PATH_MAX], buf2[_POSIX_PATH_MAX];
	char umpath[_POSIX_PATH_MAX], uvpath[_POSIX_PATH_MAX], tdpath[_POSIX_PATH_MAX];

	if (stat( box, &st ) || !S_ISDIR(st.st_mode)) {
		fprintf( stderr, "'%s' is no Maildir mailbox.\n", box );
		return 1;
	}

	nfsnprintf( umpath, sizeof(umpath), "%s/.isyncuidmap.db", box );
	nfsnprintf( uvpath, sizeof(uvpath), "%s/.uidvalidity", box );
	if (altmap)
		dpath = umpath, spath = uvpath, dbpath = tdpath;
	else
		spath = umpath, dpath = uvpath, dbpath = umpath;
	nfsnprintf( tdpath, sizeof(tdpath), "%s.tmp", dpath );
	if ((sfd = open( spath, O_RDWR )) < 0) {
		if (errno != ENOENT)
			perror( spath );
		return 1;
	}
	if (fcntl( sfd, F_SETLKW, &lck )) {
		perror( spath );
		goto sbork;
	}
	if ((dfd = open( tdpath, O_RDWR|O_CREAT, 0600 )) < 0) {
		perror( tdpath );
		goto sbork;
	}
	if (db_create( &db, 0, 0 )) {
		fputs( "Error: db_create() failed\n", stderr );
		goto tbork;
	}
	if ((ret = (db->open)( db, 0, dbpath, 0, DB_HASH, DB_CREATE, 0 ))) {
		db->err( db, ret, "Error: db->open(%s)", dbpath );
	  dbork:
		db->close( db, 0 );
	  tbork:
		unlink( tdpath );
		close( dfd );
	  sbork:
		close( sfd );
		return 1;
	}
	key.data = (void *)"UIDVALIDITY";
	key.size = 11;
	if (altmap) {
		if ((n = read( sfd, buf, sizeof(buf) )) <= 0 ||
		    (buf[n] = 0, sscanf( buf, "%d\n%d", &uv[0], &uv[1] ) != 2))
		{
			fprintf( stderr, "Error: cannot read UIDVALIDITY of '%s'.\n", box );
			goto dbork;
		}
		value.data = uv;
		value.size = sizeof(uv);
		if ((ret = db->put( db, 0, &key, &value, 0 ))) {
			db->err( db, ret, "Error: cannot write UIDVALIDITY for '%s'", box );
			goto dbork;
		}
	} else {
		if ((ret = db->get( db, 0, &key, &value, 0 ))) {
			db->err( db, ret, "Error: cannot read UIDVALIDITY of '%s'", box );
			goto dbork;
		}
		n = sprintf( buf, "%d\n%d\n", ((int *)value.data)[0], ((int *)value.data)[1] );
		if (write( dfd, buf, n ) != n) {
			fprintf( stderr, "Error: cannot write UIDVALIDITY for '%s'.\n", box );
			goto dbork;
		}
	}

  again:
	for (i = 0; i < 2; i++) {
		bl = nfsnprintf( buf, sizeof(buf), "%s/%s/", box, subdirs[i] );
		if (!(d = opendir( buf ))) {
			perror( "opendir" );
			goto dbork;
		}
		while ((e = readdir( d ))) {
			if (*e->d_name == '.')
				continue;
			nfsnprintf( buf + bl, sizeof(buf) - bl, "%s", e->d_name );
			memcpy( buf2, buf, bl );
			p = strstr( e->d_name, ",U=" );
			if (p)
				for (u = p, ru = p + 3; isdigit( (unsigned char)*ru ); ru++);
			else
				u = ru = strchr( e->d_name, ':' );
			if (u)
				ml = u - e->d_name;
			else
				ru = "", ml = sizeof(buf);
			if (altmap) {
				if (!p)
					continue;
				key.data = e->d_name;
				key.size = (size_t)(strchr( e->d_name, ',' ) - e->d_name);
				uid = atoi( p + 3 );
				value.data = &uid;
				value.size = sizeof(uid);
				if ((ret = db->put( db, 0, &key, &value, 0 ))) {
					db->err( db, ret, "Error: cannot write UID for '%s'", box );
					goto ebork;
				}
				nfsnprintf( buf2 + bl, sizeof(buf2) - bl, "%.*s%s", ml, e->d_name, ru );
			} else {
				s = strpbrk( e->d_name, ",:" );
				key.data = e->d_name;
				key.size = s ? (size_t)(s - e->d_name) : strlen( e->d_name );
				if ((ret = db->get( db, 0, &key, &value, 0 ))) {
					if (ret != DB_NOTFOUND) {
						db->err( db, ret, "Error: cannot read UID for '%s'", box );
						goto ebork;
					}
					continue;
				}
				uid = *(int *)value.data;
				nfsnprintf( buf2 + bl, sizeof(buf2) - bl, "%.*s,U=%d%s", ml, e->d_name, uid, ru );
			}
			if (rename( buf, buf2 )) {
				if (errno == ENOENT)
					goto again;
				perror( buf );
			  ebork:
				closedir( d );
				goto dbork;
			}

		}
		closedir( d );
	}

	db->close( db, 0 );
	close( dfd );
	if (rename( tdpath, dpath )) {
		perror( dpath );
		return 1;
	}
	if (unlink( spath ))
		perror( spath );
	close( sfd );
	return 0;
}

int
main( int argc, char **argv )
{
	int oint, ret, altmap = 0;

	for (oint = 1; oint < argc; oint++) {
		if (!strcmp( argv[oint], "-h" ) || !strcmp( argv[oint], "--help" )) {
			puts(
"Usage: " EXE " [-a] mailbox...\n"
"  -a, --alt      convert to alternative (DB based) UID scheme\n"
"  -n, --native   convert to native (file name based) UID scheme (default)\n"
"  -h, --help     show this help message\n"
"  -v, --version  display version"
			);
			return 0;
		} else if (!strcmp( argv[oint], "-v" ) || !strcmp( argv[oint], "--version" )) {
			puts( EXE " " VERSION " - Maildir UID scheme converter" );
			return 0;
		} else if (!strcmp( argv[oint], "-a" ) || !strcmp( argv[oint], "--alt" )) {
			altmap = 1;
		} else if (!strcmp( argv[oint], "-n" ) || !strcmp( argv[oint], "--native" )) {
			altmap = 0;
		} else if (!strcmp( argv[oint], "--" )) {
			oint++;
			break;
		} else if (argv[oint][0] == '-') {
			fprintf( stderr, "Unrecognized option '%s'. Try " EXE " -h\n", argv[oint] );
			return 1;
		} else
			break;
	}
	if (oint == argc) {
		fprintf( stderr, "Mailbox specification missing. Try " EXE " -h\n" );
		return 1;
	}
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	ret = 0;
	for (; oint < argc; oint++)
		ret |= convert( argv[oint], altmap );
	return ret;
}

