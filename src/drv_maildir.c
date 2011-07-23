/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "isync.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>
#include <time.h>

#define USE_DB 1
#ifdef __linux__
# define LEGACY_FLOCK 1
#endif

#ifdef USE_DB
#include <db.h>
#endif /* USE_DB */

typedef struct maildir_store_conf {
	store_conf_t gen;
	char *inbox;
#ifdef USE_DB
	int alt_map;
#endif /* USE_DB */
} maildir_store_conf_t;

typedef struct maildir_message {
	message_t gen;
	char *base;
	char tuid[TUIDL];
} maildir_message_t;

typedef struct maildir_store {
	store_t gen;
	int uvfd, uvok, nuid;
	int minuid, maxuid, nexcs, *excs;
#ifdef USE_DB
	DB *db;
#endif /* USE_DB */
} maildir_store_t;

#ifdef USE_DB
static DBT key, value; /* no need to be reentrant, and this saves lots of memset()s */
#endif /* USE_DB */
static struct flock lck;

static int MaildirCount;

static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static unsigned char
maildir_parse_flags( const char *base )
{
	const char *s;
	unsigned i;
	unsigned char flags;

	flags = 0;
	if ((s = strstr( base, ":2," )))
		for (s += 3, i = 0; i < as(Flags); i++)
			if (strchr( s, Flags[i] ))
				flags |= (1 << i);
	return flags;
}

static void
maildir_open_store( store_conf_t *conf,
                    void (*cb)( store_t *ctx, void *aux ), void *aux )
{
	maildir_store_t *ctx;
	struct stat st;

	if (stat( conf->path, &st ) || !S_ISDIR(st.st_mode)) {
		error( "Maildir error: cannot open store %s\n", conf->path );
		cb( 0, aux );
		return;
	}
	ctx = nfcalloc( sizeof(*ctx) );
	ctx->gen.conf = conf;
	ctx->uvfd = -1;
	cb( &ctx->gen, aux );
}

static void
free_maildir_messages( message_t *msg )
{
	message_t *tmsg;

	for (; (tmsg = msg); msg = tmsg) {
		tmsg = msg->next;
		free( ((maildir_message_t *)msg)->base );
		free( msg );
	}
}

static void
maildir_cleanup( store_t *gctx )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;

	free_maildir_messages( gctx->msgs );
#ifdef USE_DB
	if (ctx->db)
		ctx->db->close( ctx->db, 0 );
#endif /* USE_DB */
	free( gctx->path );
	free( ctx->excs );
	if (ctx->uvfd >= 0)
		close( ctx->uvfd );
}

static void
maildir_disown_store( store_t *gctx )
{
	maildir_cleanup( gctx );
	free_string_list( gctx->boxes );
	free( gctx );
}

static store_t *
maildir_own_store( store_conf_t *conf )
{
	(void)conf;
	return 0;
}

static void
maildir_cleanup_drv( void )
{
}

static void
maildir_invoke_bad_callback( store_t *ctx )
{
	ctx->bad_callback( ctx->bad_callback_aux );
}

static void
maildir_list( store_t *gctx,
              void (*cb)( int sts, void *aux ), void *aux )
{
	DIR *dir;
	struct dirent *de;

	if (!(dir = opendir( gctx->conf->path ))) {
		error( "%s: %s\n", gctx->conf->path, strerror(errno) );
		maildir_invoke_bad_callback( gctx );
		cb( DRV_CANCELED, aux );
		return;
	}
	while ((de = readdir( dir ))) {
		const char *inbox = ((maildir_store_conf_t *)gctx->conf)->inbox;
		int bl;
		struct stat st;
		char buf[PATH_MAX];

		if (*de->d_name == '.')
			continue;
		bl = nfsnprintf( buf, sizeof(buf), "%s%s/cur", gctx->conf->path, de->d_name );
		if (stat( buf, &st ) || !S_ISDIR(st.st_mode))
			continue;
		add_string_list( &gctx->boxes,
		                 !memcmp( buf, inbox, bl - 4 ) && !inbox[bl - 4] ? "INBOX" : de->d_name );
	}
	closedir (dir);

	cb( DRV_OK, aux );
}

static const char *subdirs[] = { "cur", "new", "tmp" };

typedef struct {
	char *base;
	int size;
	unsigned uid:31, recent:1;
	char tuid[TUIDL];
} msg_t;

typedef struct {
	msg_t *ents;
	int nents, nalloc;
} msglist_t;

static void
maildir_free_scan( msglist_t *msglist )
{
	int i;

	if (msglist->ents) {
		for (i = 0; i < msglist->nents; i++)
			free( msglist->ents[i].base );
		free( msglist->ents );
	}
}

#define _24_HOURS (3600 * 24)

static int
maildir_validate( const char *prefix, const char *box, int create, maildir_store_t *ctx )
{
	DIR *dirp;
	struct dirent *entry;
	time_t now;
	int i, j, bl;
	struct stat st;
	char buf[_POSIX_PATH_MAX];

	bl = nfsnprintf( buf, sizeof(buf) - 4, "%s%s/", prefix, box );
	if (stat( buf, &st )) {
		if (errno == ENOENT) {
			if (create) {
				if (mkdir( buf, 0700 )) {
					error( "Maildir error: mkdir %s: %s (errno %d)\n",
					       buf, strerror(errno), errno );
					maildir_invoke_bad_callback( &ctx->gen );
					return DRV_CANCELED;
				}
			  mkdirs:
				for (i = 0; i < 3; i++) {
					memcpy( buf + bl, subdirs[i], 4 );
					if (mkdir( buf, 0700 )) {
						error( "Maildir error: mkdir %s: %s (errno %d)\n",
						       buf, strerror(errno), errno );
						return DRV_BOX_BAD;
					}
				}
			} else {
				error( "Maildir error: mailbox '%s' does not exist\n", buf );
				return DRV_BOX_BAD;
			}
		} else {
			error( "Maildir error: stat %s: %s (errno %d)\n",
			       buf, strerror(errno), errno );
			return DRV_BOX_BAD;
		}
	} else {
		for (i = j = 0; i < 3; i++) {
			memcpy( buf + bl, subdirs[i], 4 );
			if (!stat( buf, &st ) && S_ISDIR(st.st_mode))
				j++;
		}
		if (!j)
			goto mkdirs;
		if (j != 3) {
			error( "Maildir error: '%.*s' is no valid mailbox\n", bl, buf );
			return DRV_BOX_BAD;
		}
		memcpy( buf + bl, "tmp/", 5 );
		bl += 4;
		if (!(dirp = opendir( buf ))) {
			error( "Maildir error: opendir: %s: %s (errno %d)\n",
			       buf, strerror(errno), errno );
			return DRV_BOX_BAD;
		}
		time( &now );
		while ((entry = readdir( dirp ))) {
			nfsnprintf( buf + bl, sizeof(buf) - bl, "%s", entry->d_name );
			if (stat( buf, &st ))
				error( "Maildir error: stat: %s: %s (errno %d)\n",
				       buf, strerror(errno), errno );
			else if (S_ISREG(st.st_mode) && now - st.st_ctime >= _24_HOURS) {
				/* this should happen infrequently enough that it won't be
				 * bothersome to the user to display when it occurs.
				 */
				info( "Maildir notice: removing stale file %s\n", buf );
				if (unlink( buf ))
					error( "Maildir error: unlink: %s: %s (errno %d)\n",
					       buf, strerror(errno), errno );
			}
		}
		closedir( dirp );
	}
	return DRV_OK;
}

#ifdef USE_DB
static void
make_key( DBT *tkey, char *name )
{
	char *u = strpbrk( name, ":," );
	tkey->data = name;
	tkey->size = u ? (size_t)(u - name) : strlen( name );
}

static int
maildir_set_uid( maildir_store_t *ctx, const char *name, int *uid )
{
	int ret, uv[2];

	if (uid)
		*uid = ++ctx->nuid;
	key.data = (void *)"UIDVALIDITY";
	key.size = 11;
	uv[0] = ctx->gen.uidvalidity;
	uv[1] = ctx->nuid;
	value.data = uv;
	value.size = sizeof(uv);
	if ((ret = ctx->db->put( ctx->db, 0, &key, &value, 0 ))) {
	  tbork:
		ctx->db->err( ctx->db, ret, "Maildir error: db->put()" );
	  bork:
		ctx->db->close( ctx->db, 0 );
		ctx->db = 0;
		return DRV_BOX_BAD;
	}
	if (uid) {
		make_key( &key, (char *)name );
		value.data = uid;
		value.size = sizeof(*uid);
		if ((ret = ctx->db->put( ctx->db, 0, &key, &value, 0 )))
			goto tbork;
	}
	if ((ret = ctx->db->sync( ctx->db, 0 ))) {
		ctx->db->err( ctx->db, ret, "Maildir error: db->sync()" );
		goto bork;
	}
	return DRV_OK;
}
#endif /* USE_DB */

static int
maildir_store_uid( maildir_store_t *ctx )
{
	int n;
	char buf[128];

	n = sprintf( buf, "%d\n%d\n", ctx->gen.uidvalidity, ctx->nuid );
	lseek( ctx->uvfd, 0, SEEK_SET );
	if (write( ctx->uvfd, buf, n ) != n || ftruncate( ctx->uvfd, n )) {
		error( "Maildir error: cannot write UIDVALIDITY.\n" );
		return DRV_BOX_BAD;
	}
	return DRV_OK;
}

static int
maildir_init_uid( maildir_store_t *ctx, const char *msg )
{
	info( "Maildir notice: %s.\n", msg ? msg : "cannot read UIDVALIDITY, creating new" );
	ctx->gen.uidvalidity = time( 0 );
	ctx->nuid = 0;
	ctx->uvok = 0;
#ifdef USE_DB
	if (ctx->db) {
		u_int32_t count;
		ctx->db->truncate( ctx->db, 0, &count, 0 );
		return maildir_set_uid( ctx, 0, 0 );
	}
#endif /* USE_DB */
	return maildir_store_uid( ctx );
}

static int
maildir_uidval_lock( maildir_store_t *ctx )
{
	int n;
	char buf[128];

#ifdef LEGACY_FLOCK
	/* This is legacy only */
	if (flock( ctx->uvfd, LOCK_EX ) < 0) {
		error( "Maildir error: cannot flock UIDVALIDITY.\n" );
		return DRV_BOX_BAD;
	}
#endif
	/* This (theoretically) works over NFS. Let's hope nobody else did
	   the same in the opposite order, as we'd deadlock then. */
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
	lck.l_type = F_WRLCK;
	if (fcntl( ctx->uvfd, F_SETLKW, &lck )) {
		error( "Maildir error: cannot fcntl lock UIDVALIDITY.\n" );
		return DRV_BOX_BAD;
	}
	lseek( ctx->uvfd, 0, SEEK_SET );
	if ((n = read( ctx->uvfd, buf, sizeof(buf) )) <= 0 ||
	    (buf[n] = 0, sscanf( buf, "%d\n%d", &ctx->gen.uidvalidity, &ctx->nuid ) != 2)) {
		return maildir_init_uid( ctx, 0 );
	} else
		ctx->uvok = 1;
	return DRV_OK;
}

static void
maildir_uidval_unlock( maildir_store_t *ctx )
{
	lck.l_type = F_UNLCK;
	fcntl( ctx->uvfd, F_SETLK, &lck );
#ifdef LEGACY_FLOCK
	/* This is legacy only */
	flock( ctx->uvfd, LOCK_UN );
#endif
}

static int
maildir_obtain_uid( maildir_store_t *ctx, int *uid )
{
	*uid = ++ctx->nuid;
	return maildir_store_uid( ctx );
}

static int
maildir_compare( const void *l, const void *r )
{
	msg_t *lm = (msg_t *)l, *rm = (msg_t *)r;
	char *ldot, *rdot, *ldot2, *rdot2, *lseq, *rseq;
	int ret, llen, rlen;

	if ((ret = lm->uid - rm->uid))
		return ret;

	/* No UID, so sort by arrival date. We should not do this, but we rely
	   on the suggested unique file name scheme - we have no choice. */
	/* The first field are always the seconds. Alphabetical sort should be
	   faster than numeric. */
	if (!(ldot = strchr( lm->base, '.' )) || !(rdot = strchr( rm->base, '.' )))
		goto stronly; /* Should never happen ... */
	llen = ldot - lm->base, rlen = rdot - rm->base;
	/* The shorter number is smaller. Really. This won't trigger with any
	   mail created after Sep 9 2001 anyway. */
	if ((ret = llen - rlen))
		return ret;
	if ((ret = memcmp( lm->base, rm->base, llen )))
		return ret;

	ldot++, rdot++;

	if ((llen = strtol( ldot, &ldot2, 10 ))) {
		if (!(rlen = strtol( rdot, &rdot2, 10 )))
			goto stronly; /* Comparing apples to oranges ... */
		/* Classical PID specs */
		if ((ret = llen - rlen)) {
		  retpid:
			/* Handle PID wraparound. This works only on systems
			   where PIDs are not reused too fast */
			if (ret > 20000 || ret < -20000)
				ret = -ret;
			return ret;
		}
		return (*ldot2 != '_' ? 0 : atoi( ldot2 + 1 )) -
		       (*rdot2 != '_' ? 0 : atoi( rdot2 + 1 ));
	}

	if (!(ldot2 = strchr( ldot, '.' )) || !(rdot2 = strchr( rdot, '.' )))
		goto stronly; /* Should never happen ... */
	llen = ldot2 - ldot, rlen = rdot2 - rdot;

	if (((lseq = memchr( ldot, '#', llen )) && (rseq = memchr( rdot, '#', rlen ))) ||
	    ((lseq = memchr( ldot, 'M', llen )) && (rseq = memchr( rdot, 'M', rlen ))))
		return atoi( lseq + 1 ) - atoi( rseq + 1 );

	if ((lseq = memchr( ldot, 'P', llen )) && (rseq = memchr( rdot, 'P', rlen ))) {
		if ((ret = atoi( lseq + 1 ) - atoi( rseq + 1 )))
			goto retpid;
		if ((lseq = memchr( ldot, 'Q', llen )) && (rseq = memchr( rdot, 'Q', rlen )))
			return atoi( lseq + 1 ) - atoi( rseq + 1 );
	}

  stronly:
	/* Fall-back, so the sort order is defined at all */
	return strcmp( lm->base, rm->base );
}

static int
maildir_scan( maildir_store_t *ctx, msglist_t *msglist )
{
	DIR *d;
	FILE *f;
	struct dirent *e;
	const char *u, *ru;
#ifdef USE_DB
	DB *tdb;
	DBC *dbc;
#endif /* USE_DB */
	msg_t *entry;
	int i, j, uid, bl, fnl, ret;
	struct stat st;
	char buf[_POSIX_PATH_MAX], nbuf[_POSIX_PATH_MAX];

#ifdef USE_DB
	if (!ctx->db)
#endif /* USE_DB */
		if ((ret = maildir_uidval_lock( ctx )) != DRV_OK)
			return ret;

  again:
	msglist->ents = 0;
	msglist->nents = msglist->nalloc = 0;
	ctx->gen.count = ctx->gen.recent = 0;
	if (ctx->uvok || ctx->maxuid == INT_MAX) {
#ifdef USE_DB
		if (ctx->db) {
			if (db_create( &tdb, 0, 0 )) {
				fputs( "Maildir error: db_create() failed\n", stderr );
				return DRV_BOX_BAD;
			}
			if ((tdb->open)( tdb, 0, 0, 0, DB_HASH, DB_CREATE, 0 )) {
				fputs( "Maildir error: tdb->open() failed\n", stderr );
				tdb->close( tdb, 0 );
				return DRV_BOX_BAD;
			}
		}
#endif /* USE_DB */
		bl = nfsnprintf( buf, sizeof(buf) - 4, "%s/", ctx->gen.path );
		for (i = 0; i < 2; i++) {
			memcpy( buf + bl, subdirs[i], 4 );
			if (!(d = opendir( buf ))) {
				perror( buf );
#ifdef USE_DB
				if (!ctx->db)
#endif /* USE_DB */
					maildir_uidval_unlock( ctx );
#ifdef USE_DB
			  bork:
#endif /* USE_DB */
				maildir_free_scan( msglist );
#ifdef USE_DB
				if (ctx->db)
					tdb->close( tdb, 0 );
#endif /* USE_DB */
				return DRV_BOX_BAD;
			}
			while ((e = readdir( d ))) {
				if (*e->d_name == '.')
					continue;
				ctx->gen.count++;
				ctx->gen.recent += i;
#ifdef USE_DB
				if (ctx->db) {
					make_key( &key, e->d_name );
					if ((ret = ctx->db->get( ctx->db, 0, &key, &value, 0 ))) {
						if (ret != DB_NOTFOUND) {
							ctx->db->err( ctx->db, ret, "Maildir error: db->get()" );
							ctx->db->close( ctx->db, 0 );
							ctx->db = 0;
							goto bork;
						}
						uid = INT_MAX;
					} else {
						value.size = 0;
						if ((ret = tdb->put( tdb, 0, &key, &value, 0 ))) {
							tdb->err( tdb, ret, "Maildir error: tdb->put()" );
							goto bork;
						}
						uid = *(int *)value.data;
					}
				} else
#endif /* USE_DB */
				{
					uid = (ctx->uvok && (u = strstr( e->d_name, ",U=" ))) ? atoi( u + 3 ) : 0;
					if (!uid)
						uid = INT_MAX;
				}
				if (uid <= ctx->maxuid) {
					if (uid < ctx->minuid) {
						for (j = 0; j < ctx->nexcs; j++)
							if (ctx->excs[j] == uid)
								goto oke;
						continue;
					  oke: ;
					}
					if (msglist->nalloc == msglist->nents) {
						msglist->nalloc = msglist->nalloc * 2 + 100;
						msglist->ents = nfrealloc( msglist->ents, msglist->nalloc * sizeof(msg_t) );
					}
					entry = &msglist->ents[msglist->nents++];
					entry->base = nfstrdup( e->d_name );
					entry->uid = uid;
					entry->recent = i;
					entry->size = 0;
					entry->tuid[0] = 0;
				}
			}
			closedir( d );
		}
#ifdef USE_DB
		if (ctx->db) {
			if ((ret = ctx->db->cursor( ctx->db, 0, &dbc, 0 )))
				ctx->db->err( ctx->db, ret, "Maildir error: db->cursor()" );
			else {
				for (;;) {
					if ((ret = dbc->c_get( dbc, &key, &value, DB_NEXT ))) {
						if (ret != DB_NOTFOUND)
							ctx->db->err( ctx->db, ret, "Maildir error: db->c_get()" );
						break;
					}
					if ((key.size != 11 || memcmp( key.data, "UIDVALIDITY", 11 )) &&
					    (ret = tdb->get( tdb, 0, &key, &value, 0 ))) {
						if (ret != DB_NOTFOUND) {
							tdb->err( tdb, ret, "Maildir error: tdb->get()" );
							break;
						}
						if ((ret = dbc->c_del( dbc, 0 ))) {
							ctx->db->err( ctx->db, ret, "Maildir error: db->c_del()" );
							break;
						}
					}
				}
				dbc->c_close( dbc );
			}
			tdb->close( tdb, 0 );
		}
#endif /* USE_DB */
		qsort( msglist->ents, msglist->nents, sizeof(msg_t), maildir_compare );
		for (uid = i = 0; i < msglist->nents; i++) {
			entry = &msglist->ents[i];
			if (entry->uid != INT_MAX) {
				if (uid == entry->uid) {
					if ((ret = maildir_init_uid( ctx, "duplicate UID; changing UIDVALIDITY" )) != DRV_OK) {
						maildir_free_scan( msglist );
						return ret;
					}
					maildir_free_scan( msglist );
					goto again;
				}
				uid = entry->uid;
				if (ctx->gen.opts & (OPEN_SIZE|OPEN_FIND))
					nfsnprintf( buf + bl, sizeof(buf) - bl, "%s/%s", subdirs[entry->recent], entry->base );
#ifdef USE_DB
			} else if (ctx->db) {
				if ((ret = maildir_set_uid( ctx, entry->base, &uid )) != DRV_OK) {
					maildir_free_scan( msglist );
					return ret;
				}
				entry->uid = uid;
				if (ctx->gen.opts & (OPEN_SIZE|OPEN_FIND))
					nfsnprintf( buf + bl, sizeof(buf) - bl, "%s/%s", subdirs[entry->recent], entry->base );
#endif /* USE_DB */
			} else {
				if ((ret = maildir_obtain_uid( ctx, &uid )) != DRV_OK) {
					maildir_free_scan( msglist );
					return ret;
				}
				entry->uid = uid;
				if ((u = strstr( entry->base, ",U=" )))
					for (ru = u + 3; isdigit( (unsigned char)*ru ); ru++);
				else
					u = ru = strchr( entry->base, ':' );
				fnl = (u ?
					nfsnprintf( buf + bl, sizeof(buf) - bl, "%s/%.*s,U=%d%s", subdirs[entry->recent], (int)(u - entry->base), entry->base, uid, ru ) :
					nfsnprintf( buf + bl, sizeof(buf) - bl, "%s/%s,U=%d", subdirs[entry->recent], entry->base, uid ))
					+ 1 - 4;
				memcpy( nbuf, buf, bl + 4 );
				nfsnprintf( nbuf + bl + 4, sizeof(nbuf) - bl - 4, "%s", entry->base );
				if (rename( nbuf, buf )) {
				  notok:
					if (errno != ENOENT) {
						perror( buf );
						maildir_uidval_unlock( ctx );
						maildir_free_scan( msglist );
						return DRV_BOX_BAD;
					}
					maildir_free_scan( msglist );
					goto again;
				}
				free( entry->base );
				entry->base = nfmalloc( fnl );
				memcpy( entry->base, buf + bl + 4, fnl );
			}
			if (ctx->gen.opts & OPEN_SIZE) {
				if (stat( buf, &st ))
					goto notok;
				entry->size = st.st_size;
			}
			if (ctx->gen.opts & OPEN_FIND) {
				if (!(f = fopen( buf, "r" )))
					goto notok;
				while (fgets( nbuf, sizeof(nbuf), f )) {
					if (!nbuf[0] || nbuf[0] == '\n')
						break;
					if (!memcmp( nbuf, "X-TUID: ", 8 ) && nbuf[8 + TUIDL] == '\n') {
						memcpy( entry->tuid, nbuf + 8, TUIDL );
						break;
					}
				}
				fclose( f );
			}
		}
		ctx->uvok = 1;
	}
#ifdef USE_DB
	if (!ctx->db)
#endif /* ! USE_DB */
		maildir_uidval_unlock( ctx );
	return DRV_OK;
}

static void
maildir_init_msg( maildir_store_t *ctx, maildir_message_t *msg, msg_t *entry )
{
	msg->base = entry->base;
	entry->base = 0; /* prevent deletion */
	msg->gen.size = entry->size;
	strncpy( msg->tuid, entry->tuid, TUIDL );
	if (entry->recent)
		msg->gen.status |= M_RECENT;
	if (ctx->gen.opts & OPEN_FLAGS) {
		msg->gen.status |= M_FLAGS;
		msg->gen.flags = maildir_parse_flags( msg->base );
	} else
		msg->gen.flags = 0;
}

static void
maildir_app_msg( maildir_store_t *ctx, message_t ***msgapp, msg_t *entry )
{
	maildir_message_t *msg = nfmalloc( sizeof(*msg) );
	msg->gen.next = **msgapp;
	**msgapp = &msg->gen;
	*msgapp = &msg->gen.next;
	msg->gen.uid = entry->uid;
	msg->gen.status = 0;
	maildir_init_msg( ctx, msg, entry );
}

static void
maildir_prepare_paths( store_t *gctx )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;

	maildir_cleanup( gctx );
	gctx->msgs = 0;
	ctx->uvfd = -1;
#ifdef USE_DB
	ctx->db = 0;
#endif /* USE_DB */
	if (!strcmp( gctx->name, "INBOX" ))
		gctx->path = nfstrdup( ((maildir_store_conf_t *)gctx->conf)->inbox );
	else
		nfasprintf( &gctx->path, "%s%s", gctx->conf->path, gctx->name );
}

static void
maildir_prepare_opts( store_t *gctx, int opts )
{
	if (opts & OPEN_SETFLAGS)
		opts |= OPEN_OLD;
	if (opts & OPEN_EXPUNGE)
		opts |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	gctx->opts = opts;
}

static void
maildir_select( store_t *gctx, int minuid, int maxuid, int *excs, int nexcs,
                void (*cb)( int sts, void *aux ), void *aux )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;
	message_t **msgapp;
	msglist_t msglist;
	int i;
#ifdef USE_DB
	int ret;
#endif /* USE_DB */
	char uvpath[_POSIX_PATH_MAX];

	ctx->minuid = minuid;
	ctx->maxuid = maxuid;
	ctx->excs = nfrealloc( excs, nexcs * sizeof(int) );
	ctx->nexcs = nexcs;

	if ((ret = maildir_validate( gctx->path, "", ctx->gen.opts & OPEN_CREATE, ctx )) != DRV_OK) {
		cb( ret, aux );
		return;
	}

	nfsnprintf( uvpath, sizeof(uvpath), "%s/.uidvalidity", gctx->path );
#ifndef USE_DB
	if ((ctx->uvfd = open( uvpath, O_RDWR|O_CREAT, 0600 )) < 0) {
		perror( uvpath );
		cb( DRV_BOX_BAD, aux );
		return;
	}
#else
	if ((ctx->uvfd = open( uvpath, O_RDWR, 0600 )) < 0) {
		nfsnprintf( uvpath, sizeof(uvpath), "%s/.isyncuidmap.db", gctx->path );
		if ((ctx->uvfd = open( uvpath, O_RDWR, 0600 )) < 0) {
			if (((maildir_store_conf_t *)gctx->conf)->alt_map) {
				if ((ctx->uvfd = open( uvpath, O_RDWR|O_CREAT, 0600 )) >= 0)
					goto dbok;
			} else {
				nfsnprintf( uvpath, sizeof(uvpath), "%s/.uidvalidity", gctx->path );
				if ((ctx->uvfd = open( uvpath, O_RDWR|O_CREAT, 0600 )) >= 0)
					goto fnok;
			}
			perror( uvpath );
			cb( DRV_BOX_BAD, aux );
			return;
		}
	  dbok:
#if SEEK_SET != 0
		lck.l_whence = SEEK_SET;
#endif
		lck.l_type = F_WRLCK;
		if (fcntl( ctx->uvfd, F_SETLKW, &lck )) {
			perror( uvpath );
		  bork:
			close( ctx->uvfd );
			ctx->uvfd = -1;
			cb( DRV_BOX_BAD, aux );
			return;
		}
		if (db_create( &ctx->db, 0, 0 )) {
			fputs( "Maildir error: db_create() failed\n", stderr );
			goto bork;
		}
		if ((ret = (ctx->db->open)( ctx->db, 0, uvpath, 0, DB_HASH, DB_CREATE, 0 ))) {
			ctx->db->err( ctx->db, ret, "Maildir error: db->open(%s)", uvpath );
		  dbork:
			ctx->db->close( ctx->db, 0 );
			goto bork;
		}
		key.data = (void *)"UIDVALIDITY";
		key.size = 11;
		if ((ret = ctx->db->get( ctx->db, 0, &key, &value, 0 ))) {
			if (ret != DB_NOTFOUND) {
				ctx->db->err( ctx->db, ret, "Maildir error: db->get()" );
				goto dbork;
			}
			if (maildir_init_uid( ctx, 0 ) != DRV_OK)
				goto dbork;
		} else {
			ctx->gen.uidvalidity = ((int *)value.data)[0];
			ctx->nuid = ((int *)value.data)[1];
			ctx->uvok = 1;
		}
	}
  fnok:
#endif /* USE_DB */

	if (maildir_scan( ctx, &msglist ) != DRV_OK) {
		cb( DRV_BOX_BAD, aux );
		return;
	}
	msgapp = &ctx->gen.msgs;
	for (i = 0; i < msglist.nents; i++)
		maildir_app_msg( ctx, &msgapp, msglist.ents + i );
	maildir_free_scan( &msglist );

	cb( DRV_OK, aux );
}

static int
maildir_rescan( maildir_store_t *ctx )
{
	message_t **msgapp;
	maildir_message_t *msg;
	msglist_t msglist;
	int i;

	if (maildir_scan( ctx, &msglist ) != DRV_OK)
		return DRV_BOX_BAD;
	ctx->gen.recent = 0;
	for (msgapp = &ctx->gen.msgs, i = 0;
	     (msg = (maildir_message_t *)*msgapp) || i < msglist.nents; )
	{
		if (!msg) {
#if 0
			debug( "adding new message %d\n", msglist.ents[i].uid );
			maildir_app_msg( ctx, &msgapp, msglist.ents + i );
#else
			debug( "ignoring new message %d\n", msglist.ents[i].uid );
#endif
			i++;
		} else if (i >= msglist.nents) {
			debug( "purging deleted message %d\n", msg->gen.uid );
			msg->gen.status = M_DEAD;
			msgapp = &msg->gen.next;
		} else if (msglist.ents[i].uid < msg->gen.uid) {
			/* this should not happen, actually */
#if 0
			debug( "adding new message %d\n", msglist.ents[i].uid );
			maildir_app_msg( ctx, &msgapp, msglist.ents + i );
#else
			debug( "ignoring new message %d\n", msglist.ents[i].uid );
#endif
			i++;
		} else if (msglist.ents[i].uid > msg->gen.uid) {
			debug( "purging deleted message %d\n", msg->gen.uid );
			msg->gen.status = M_DEAD;
			msgapp = &msg->gen.next;
		} else {
			debug( "updating message %d\n", msg->gen.uid );
			msg->gen.status &= ~(M_FLAGS|M_RECENT);
			free( msg->base );
			maildir_init_msg( ctx, msg, msglist.ents + i );
			i++, msgapp = &msg->gen.next;
		}
	}
	maildir_free_scan( &msglist );
	return DRV_OK;
}

static int
maildir_again( maildir_store_t *ctx, maildir_message_t *msg, const char *fn )
{
	int ret;

	if (errno != ENOENT) {
		perror( fn );
		return DRV_BOX_BAD;
	}
	if ((ret = maildir_rescan( ctx )) != DRV_OK)
		return ret;
	return (msg->gen.status & M_DEAD) ? DRV_MSG_BAD : DRV_OK;
}

static void
maildir_fetch_msg( store_t *gctx, message_t *gmsg, msg_data_t *data,
                   void (*cb)( int sts, void *aux ), void *aux )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;
	maildir_message_t *msg = (maildir_message_t *)gmsg;
	int fd, ret;
	struct stat st;
	char buf[_POSIX_PATH_MAX];

	for (;;) {
		nfsnprintf( buf, sizeof(buf), "%s/%s/%s", gctx->path, subdirs[gmsg->status & M_RECENT], msg->base );
		if ((fd = open( buf, O_RDONLY )) >= 0)
			break;
		if ((ret = maildir_again( ctx, msg, buf )) != DRV_OK) {
			cb( ret, aux );
			return;
		}
	}
	fstat( fd, &st );
	data->len = st.st_size;
	data->data = nfmalloc( data->len );
	if (read( fd, data->data, data->len ) != data->len) {
		perror( buf );
		close( fd );
		cb( DRV_MSG_BAD, aux );
		return;
	}
	close( fd );
	if (!(gmsg->status & M_FLAGS))
		data->flags = maildir_parse_flags( msg->base );
	cb( DRV_OK, aux );
}

static int
maildir_make_flags( int flags, char *buf )
{
	unsigned i, d;

	buf[0] = ':';
	buf[1] = '2';
	buf[2] = ',';
	for (d = 3, i = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return d;
}

static void
maildir_store_msg( store_t *gctx, msg_data_t *data, int to_trash,
                   void (*cb)( int sts, int uid, void *aux ), void *aux )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;
	const char *prefix, *box;
	int ret, fd, bl, uid;
	char buf[_POSIX_PATH_MAX], nbuf[_POSIX_PATH_MAX], fbuf[NUM_FLAGS + 3], base[128];

	bl = nfsnprintf( base, sizeof(base), "%ld.%d_%d.%s", time( 0 ), Pid, ++MaildirCount, Hostname );
	if (!to_trash) {
#ifdef USE_DB
		if (ctx->db) {
			if ((ret = maildir_set_uid( ctx, base, &uid )) != DRV_OK) {
				free( data->data );
				cb( ret, 0, aux );
				return;
			}
		} else
#endif /* USE_DB */
		{
			if ((ret = maildir_uidval_lock( ctx )) != DRV_OK ||
			    (ret = maildir_obtain_uid( ctx, &uid )) != DRV_OK) {
				cb( ret, 0, aux );
				return;
			}
			maildir_uidval_unlock( ctx );
			nfsnprintf( base + bl, sizeof(base) - bl, ",U=%d", uid );
		}
		prefix = gctx->path;
		box = "";
	} else {
		prefix = gctx->conf->path;
		box = gctx->conf->trash;
	}

	maildir_make_flags( data->flags, fbuf );
	nfsnprintf( buf, sizeof(buf), "%s%s/tmp/%s%s", prefix, box, base, fbuf );
	if ((fd = open( buf, O_WRONLY|O_CREAT|O_EXCL, 0600 )) < 0) {
		if (errno != ENOENT) {
			perror( buf );
			free( data->data );
			cb( DRV_BOX_BAD, 0, aux );
			return;
		}
		if ((ret = maildir_validate( gctx->conf->path, gctx->conf->trash, 1, ctx )) != DRV_OK) {
			free( data->data );
			cb( ret, 0, aux );
			return;
		}
		if ((fd = open( buf, O_WRONLY|O_CREAT|O_EXCL, 0600 )) < 0) {
			perror( buf );
			free( data->data );
			cb( DRV_BOX_BAD, 0, aux );
			return;
		}
	}
	ret = write( fd, data->data, data->len );
	free( data->data );
	if (ret != data->len) {
		if (ret < 0)
			perror( buf );
		else
			error( "Maildir error: %s: partial write\n", buf );
		close( fd );
		cb( DRV_BOX_BAD, 0, aux );
		return;
	}
	if (close( fd ) < 0) {
		/* Quota exceeded may cause this. */
		perror( buf );
		cb( DRV_BOX_BAD, 0, aux );
		return;
	}
	/* Moving seen messages to cur/ is strictly speaking incorrect, but makes mutt happy. */
	nfsnprintf( nbuf, sizeof(nbuf), "%s%s/%s/%s%s", prefix, box, subdirs[!(data->flags & F_SEEN)], base, fbuf );
	if (rename( buf, nbuf )) {
		perror( nbuf );
		cb( DRV_BOX_BAD, 0, aux );
		return;
	}
	cb( DRV_OK, uid, aux );
}

static void
maildir_find_msg( store_t *gctx, const char *tuid,
                  void (*cb)( int sts, int uid, void *aux ), void *aux )
{
	message_t *msg;

	/* using a hash table might turn out to be more appropriate ... */
	for (msg = gctx->msgs; msg; msg = msg->next)
		if (!(msg->status & M_DEAD) && !memcmp( ((maildir_message_t *)msg)->tuid, tuid, TUIDL )) {
			cb( DRV_OK, msg->uid, aux );
			return;
		}
	cb( DRV_MSG_BAD, -1, aux );
}

static void
maildir_set_flags( store_t *gctx, message_t *gmsg, int uid, int add, int del,
                   void (*cb)( int sts, void *aux ), void *aux )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;
	maildir_message_t *msg = (maildir_message_t *)gmsg;
	char *s, *p;
	unsigned i;
	int j, ret, ol, fl, bbl, bl, tl;
	char buf[_POSIX_PATH_MAX], nbuf[_POSIX_PATH_MAX];

	(void) uid;
	bbl = nfsnprintf( buf, sizeof(buf), "%s/", gctx->path );
	memcpy( nbuf, gctx->path, bbl - 1 );
	memcpy( nbuf + bbl - 1, "/cur/", 5 );
	for (;;) {
		bl = bbl + nfsnprintf( buf + bbl, sizeof(buf) - bbl, "%s/", subdirs[gmsg->status & M_RECENT] );
		ol = strlen( msg->base );
		if ((int)sizeof(buf) - bl < ol + 3 + NUM_FLAGS)
			oob();
		memcpy( buf + bl, msg->base, ol + 1 );
		memcpy( nbuf + bl, msg->base, ol + 1 );
		if ((s = strstr( nbuf + bl, ":2," ))) {
			s += 3;
			fl = ol - (s - (nbuf + bl));
			for (i = 0; i < as(Flags); i++) {
				if ((p = strchr( s, Flags[i] ))) {
					if (del & (1 << i)) {
						memcpy( p, p + 1, fl - (p - s) );
						fl--;
					}
				} else if (add & (1 << i)) {
					for (j = 0; j < fl && Flags[i] > s[j]; j++);
					fl++;
					memmove( s + j + 1, s + j, fl - j );
					s[j] = Flags[i];
				}
			}
			tl = ol + 3 + fl;
		} else {
			tl = ol + maildir_make_flags( msg->gen.flags, nbuf + bl + ol );
		}
		if (!rename( buf, nbuf ))
			break;
		if ((ret = maildir_again( ctx, msg, buf )) != DRV_OK) {
			cb( ret, aux );
			return;
		}
	}
	free( msg->base );
	msg->base = nfmalloc( tl + 1 );
	memcpy( msg->base, nbuf + bl, tl + 1 );
	msg->gen.flags |= add;
	msg->gen.flags &= ~del;
	gmsg->status &= ~M_RECENT;

	cb( DRV_OK, aux );
}

#ifdef USE_DB
static int
maildir_purge_msg( maildir_store_t *ctx, const char *name )
{
	int ret;

	make_key( &key, (char *)name );
	if ((ret = ctx->db->del( ctx->db, 0, &key, 0 ))) {
		ctx->db->err( ctx->db, ret, "Maildir error: db->del()" );
		ctx->db->close( ctx->db, 0 );
		ctx->db = 0;
		return DRV_BOX_BAD;
	}
	return DRV_OK;
}
#endif /* USE_DB */

static void
maildir_trash_msg( store_t *gctx, message_t *gmsg,
                   void (*cb)( int sts, void *aux ), void *aux )
{
	maildir_store_t *ctx = (maildir_store_t *)gctx;
	maildir_message_t *msg = (maildir_message_t *)gmsg;
	char *s;
	int ret;
	struct stat st;
	char buf[_POSIX_PATH_MAX], nbuf[_POSIX_PATH_MAX];

	for (;;) {
		nfsnprintf( buf, sizeof(buf), "%s/%s/%s", gctx->path, subdirs[gmsg->status & M_RECENT], msg->base );
		s = strstr( msg->base, ":2," );
		nfsnprintf( nbuf, sizeof(nbuf), "%s%s/%s/%ld.%d_%d.%s%s", gctx->conf->path, gctx->conf->trash,
		            subdirs[gmsg->status & M_RECENT], time( 0 ), Pid, ++MaildirCount, Hostname, s ? s : "" );
		if (!rename( buf, nbuf ))
			break;
		if (!stat( buf, &st )) {
			if ((ret = maildir_validate( gctx->conf->path, gctx->conf->trash, 1, ctx )) != DRV_OK) {
				cb( ret, aux );
				return;
			}
			if (!rename( buf, nbuf ))
				break;
			if (errno != ENOENT) {
				perror( nbuf );
				cb( DRV_BOX_BAD, aux );
				return;
			}
		}
		if ((ret = maildir_again( ctx, msg, buf )) != DRV_OK) {
			cb( ret, aux );
			return;
		}
	}
	gmsg->status |= M_DEAD;
	gctx->count--;

#ifdef USE_DB
	if (ctx->db) {
		cb( maildir_purge_msg( ctx, msg->base ), aux );
		return;
	}
#endif /* USE_DB */
	cb( DRV_OK, aux );
}

static void
maildir_close( store_t *gctx,
               void (*cb)( int sts, void *aux ), void *aux )
{
#ifdef USE_DB
	maildir_store_t *ctx = (maildir_store_t *)gctx;
#endif /* USE_DB */
	message_t *msg;
	int basel, retry, ret;
	char buf[_POSIX_PATH_MAX];

	for (;;) {
		retry = 0;
		basel = nfsnprintf( buf, sizeof(buf), "%s/", gctx->path );
		for (msg = gctx->msgs; msg; msg = msg->next)
			if (!(msg->status & M_DEAD) && (msg->flags & F_DELETED)) {
				nfsnprintf( buf + basel, sizeof(buf) - basel, "%s/%s", subdirs[msg->status & M_RECENT], ((maildir_message_t *)msg)->base );
				if (unlink( buf )) {
					if (errno == ENOENT)
						retry = 1;
					else
						perror( buf );
				} else {
					msg->status |= M_DEAD;
					gctx->count--;
#ifdef USE_DB
					if (ctx->db && (ret = maildir_purge_msg( ctx, ((maildir_message_t *)msg)->base )) != DRV_OK) {
						cb( ret, aux );
						return;
					}
#endif /* USE_DB */
				}
			}
		if (!retry) {
			cb( DRV_OK, aux );
			return;
		}
		if ((ret = maildir_rescan( (maildir_store_t *)gctx )) != DRV_OK) {
			cb( ret, aux );
			return;
		}
	}
}

static void
maildir_cancel( store_t *gctx,
                void (*cb)( void *aux ), void *aux )
{
	(void)gctx;
	cb( aux );
}

static void
maildir_commit( store_t *gctx )
{
	(void) gctx;
}

static int
maildir_parse_store( conffile_t *cfg, store_conf_t **storep, int *err )
{
	maildir_store_conf_t *store;

	if (strcasecmp( "MaildirStore", cfg->cmd ))
		return 0;
	store = nfcalloc( sizeof(*store) );
	store->gen.driver = &maildir_driver;
	store->gen.name = nfstrdup( cfg->val );

	while (getcline( cfg ) && cfg->cmd)
		if (!strcasecmp( "Inbox", cfg->cmd ))
			store->inbox = expand_strdup( cfg->val );
		else if (!strcasecmp( "Path", cfg->cmd ))
			store->gen.path = expand_strdup( cfg->val );
#ifdef USE_DB
		else if (!strcasecmp( "AltMap", cfg->cmd ))
			store->alt_map = parse_bool( cfg );
#endif /* USE_DB */
		else
			parse_generic_store( &store->gen, cfg, err );
	if (!store->inbox)
		store->inbox = expand_strdup( "~/Maildir" );
	*storep = &store->gen;
	return 1;
}

struct driver maildir_driver = {
	0, /* XXX DRV_CRLF? */
	maildir_parse_store,
	maildir_cleanup_drv,
	maildir_open_store,
	maildir_disown_store,
	maildir_own_store,
	maildir_disown_store, /* _cancel_, but it's the same */
	maildir_list,
	maildir_prepare_paths,
	maildir_prepare_opts,
	maildir_select,
	maildir_fetch_msg,
	maildir_store_msg,
	maildir_find_msg,
	maildir_set_flags,
	maildir_trash_msg,
	maildir_close,
	maildir_cancel,
	maildir_commit,
};
