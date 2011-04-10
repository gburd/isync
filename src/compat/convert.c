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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include <db.h>

static const char *subdirs[] = { "cur", "new", "tmp" };

static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static int
parse_info( const char *s )
{
	unsigned i;
	int flags;

	flags = 0;
	if (s && *(s + 1) == '2' && *(s + 2) == ',')
		for (s += 3, i = 0; i < as(Flags); i++)
			if (strchr( s, Flags[i] ))
				flags |= (1 << i);
	return flags;
}

typedef struct {
	int uid, flags;
} msg_t;

static int
compare_uids( const void *l, const void *r )
{
	return ((msg_t *)l)->uid - ((msg_t *)r)->uid;
}

static DBT key, value;
static struct flock lck;

void
convert( config_t *box )
{
	DIR *d;
	struct dirent *e;
	char *s, *p, *mboxdir;
	FILE *fp;
	msg_t *msgs;
	DB *db;
	int i, ret, fd, uidval, maxuid, uid, rmsgs, nmsgs, uv[2];
	unsigned u;
	struct stat sb;
	char buf[_POSIX_PATH_MAX], diumname[_POSIX_PATH_MAX],
	     uvname[_POSIX_PATH_MAX], sname[_POSIX_PATH_MAX],
	     iuvname[_POSIX_PATH_MAX], imuname[_POSIX_PATH_MAX],
	     ilname[_POSIX_PATH_MAX], iumname[_POSIX_PATH_MAX];

	mboxdir = expand_strdup( box->path );
	nfsnprintf( iuvname, sizeof(iuvname), "%s/isyncuidvalidity", mboxdir );
	nfsnprintf( diumname, sizeof(iumname), "%s/.isyncuidmap.db", mboxdir );
	nfsnprintf( uvname, sizeof(uvname), "%s/.uidvalidity", mboxdir );
	if (stat( iuvname, &sb )) {
		if (!stat( diumname, &sb ))
			altmap++;
		else if (!stat( uvname, &sb ))
			altmap--;
	  err1:
		free( mboxdir );
		return;
	}
	for (i = 0; i < 3; i++) {
		nfsnprintf( buf, sizeof(buf), "%s/%s", mboxdir, subdirs[i] );
		if (stat( buf, &sb )) {
			sys_error( "ERROR: cannot access %s", buf );
			fprintf( stderr,
			         "ERROR: '%s' does not appear to be a valid maildir style mailbox\n",
			         mboxdir );
			goto err1;
		}
	}
	nfsnprintf( iumname, sizeof(iumname), "%s/isyncuidmap.db", mboxdir );
	nfsnprintf( imuname, sizeof(imuname), "%s/isyncmaxuid", mboxdir );
	nfsnprintf( ilname, sizeof(ilname), "%s/isynclock", mboxdir );
	nfsnprintf( sname, sizeof(sname), "%s/.mbsyncstate", mboxdir );

	if ((fd = open( ilname, O_WRONLY|O_CREAT, 0600 )) < 0) {
		sys_error( "Cannot create %s", ilname );
		goto err1;
	}
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	if (fcntl( fd, F_SETLKW, &lck )) {
		sys_error( "Cannot lock %s", ilname );
	  err2:
		close( fd );
		goto err1;
	}

	if (!(fp = fopen( iuvname, "r" ))) {
		sys_error( "Cannot open %s", iuvname );
		goto err2;
	}
	fscanf( fp, "%d", &uidval );
	fclose( fp );
	if (!(fp = fopen( imuname, "r" ))) {
		sys_error( "Cannot open %s", imuname );
		goto err2;
	}
	fscanf( fp, "%d", &maxuid );
	fclose( fp );

	if (!stat( iumname, &sb )) {
		if (db_create( &db, 0, 0 )) {
			fputs( "dbcreate failed\n", stderr );
			goto err2;
		}
		if ((db->open)( db, 0, iumname, 0, DB_HASH, 0, 0 )) {
			fputs( "cannot open db\n", stderr );
			db->close( db, 0 );
			goto err2;
		}
		altmap++;
	} else {
		db = 0;
		altmap--;
	}

	msgs = 0;
	rmsgs = 0;
	nmsgs = 0;
	for (i = 0; i < 2; i++) {
		nfsnprintf( buf, sizeof(buf), "%s/%s/", mboxdir, subdirs[i] );
		if (!(d = opendir( buf ))) {
			sys_error( "Cannot list %s", buf );
		  err4:
			free( msgs );
			if (db)
				db->close( db, 0 );
			goto err2;
		}
		while ((e = readdir( d ))) {
			if (*e->d_name == '.')
				continue;
			s = strchr( e->d_name, ':' );
			if (db) {
				key.data = e->d_name;
				key.size = s ? (size_t)(s - e->d_name) : strlen( e->d_name );
				if ((ret = db->get( db, 0, &key, &value, 0 ))) {
					if (ret != DB_NOTFOUND)
						db->err( db, ret, "Maildir error: db->get()" );
					continue;
				}
				uid = *(int *)value.data;
			} else if ((p = strstr( e->d_name, ",U=" )))
				uid = atoi( p + 3 );
			else
				continue;
			if (nmsgs == rmsgs) {
				rmsgs = rmsgs * 2 + 100;
				msgs = nfrealloc( msgs, rmsgs * sizeof(msg_t) );
			}
			msgs[nmsgs].uid = uid;
			msgs[nmsgs++].flags = parse_info( s );
		}
		closedir( d );
	}

	qsort( msgs, nmsgs, sizeof(msg_t), compare_uids );

	if (!(fp = fopen( sname, "w" ))) {
		sys_error( "Cannot create %s", sname );
		goto err4;
	}
	if (box->max_messages) {
		if (!nmsgs)
			i = maxuid;
		else {
			i = nmsgs - box->max_messages;
			if (i < 0)
				i = 0;
			i = msgs[i].uid - 1;
		}
	} else
		i = 0;
	fprintf( fp, "%d:%d %d:%d:%d\n", uidval, maxuid, uidval, i, maxuid );
	for (i = 0; i < nmsgs; i++) {
		fprintf( fp, "%d %d ", msgs[i].uid, msgs[i].uid );
		for (u = 0; u < as(Flags); u++)
			if (msgs[i].flags & (1 << u))
				fputc( Flags[u], fp );
		fputc( '\n', fp );
	}
	fclose( fp );

	if (db) {
		key.data = (void *)"UIDVALIDITY";
		key.size = 11;
		uv[0] = uidval;
		uv[1] = maxuid;
		value.data = uv;
		value.size = sizeof(uv);
		if ((ret = db->put( db, 0, &key, &value, 0 ))) {
			db->err( db, ret, "Maildir error: db->put()" );
			goto err4;
		}
		db->close( db, 0 );
		rename( iumname, diumname );
	} else {
		if (!(fp = fopen( uvname, "w" ))) {
			sys_error( "Cannot create %s", uvname );
			goto err4;
		}
		fprintf( fp, "%d\n%d\n", uidval, maxuid );
		fclose( fp );
	}

	unlink( iuvname );
	unlink( imuname );

	close( fd );
	unlink( ilname );

	free( msgs );
	free( mboxdir );
	return;
}
