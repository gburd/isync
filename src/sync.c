/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006 Oswald Buddenhagen <ossi@users.sf.net>
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

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

const char *str_ms[] = { "master", "slave" }, *str_hl[] = { "push", "pull" };

void
Fclose( FILE *f )
{
	if (fclose( f ) == EOF) {
		perror( "cannot close file" );
		exit( 1 );
	}
}

void
Fprintf( FILE *f, const char *msg, ... )
{
	int r;
	va_list va;

	va_start( va, msg );
	r = vfprintf( f, msg, va );
	va_end( va );
	if (r < 0) {
		perror( "cannot write file" );
		exit( 1 );
	}
}


static const char Flags[] = { 'D', 'F', 'R', 'S', 'T' };

static int
parse_flags( const char *buf )
{
	unsigned flags, i, d;

	for (flags = i = d = 0; i < as(Flags); i++)
		if (buf[d] == Flags[i]) {
			flags |= (1 << i);
			d++;
		}
	return flags;
}

static int
make_flags( int flags, char *buf )
{
	unsigned i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return d;
}


#define S_DEAD         (1<<0)
#define S_DONE         (1<<1)
#define S_DEL(ms)      (1<<(2+(ms)))
#define S_EXPIRED      (1<<4)
#define S_EXPIRE       (1<<5)
#define S_NEXPIRE      (1<<6)
#define S_EXP_S        (1<<7)

#define mvBit(in,ib,ob) ((unsigned char)(((unsigned)in) * (ob) / (ib)))

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	int uid[2];
	message_t *msg[2];
	unsigned char status, flags, aflags[2], dflags[2];
	char tuid[TUIDL];
} sync_rec_t;


/* cases:
   a) both non-null
   b) only master null
   b.1) uid[M] 0
   b.2) uid[M] -1
   b.3) master not scanned
   b.4) master gone
   c) only slave null
   c.1) uid[S] 0
   c.2) uid[S] -1
   c.3) slave not scanned
   c.4) slave gone
   d) both null
   d.1) both gone
   d.2) uid[M] 0, slave not scanned
   d.3) uid[M] -1, slave not scanned
   d.4) master gone, slave not scanned
   d.5) uid[M] 0, slave gone
   d.6) uid[M] -1, slave gone
   d.7) uid[S] 0, master not scanned
   d.8) uid[S] -1, master not scanned
   d.9) slave gone, master not scanned
   d.10) uid[S] 0, master gone
   d.11) uid[S] -1, master gone
   impossible cases: both uid[M] & uid[S] 0 or -1, both not scanned
*/

typedef struct {
	int t[2];
	void (*cb)( int sts, void *aux ), *aux;
	char *dname, *jname, *nname, *lname;
	FILE *jfp, *nfp;
	sync_rec_t *srecs, **srecadd, **osrecadd;
	channel_conf_t *chan;
	store_t *ctx[2];
	driver_t *drv[2];
	int state[2], ref_count, ret;
	int find_old_total[2], find_old_done[2];
	int new_total[2], new_done[2];
	int find_new_total[2], find_new_done[2];
	int flags_total[2], flags_done[2];
	int trash_total[2], trash_done[2];
	int maxuid[2], uidval[2], smaxxuid, lfd;
	unsigned find:1;
} sync_vars_t;

static void sync_ref( sync_vars_t *svars ) { ++svars->ref_count; }
static int sync_deref( sync_vars_t *svars );
static int deref_check_cancel( sync_vars_t *svars );
static int check_cancel( sync_vars_t *svars );

#define DRIVER_CALL_RET(call) \
	do { \
		sync_ref( svars ); \
		svars->drv[t]->call; \
		return deref_check_cancel( svars ); \
	} while (0)

#define DRIVER_CALL(call) \
	do { \
		sync_ref( svars ); \
		svars->drv[t]->call; \
		if (deref_check_cancel( svars )) \
			return; \
	} while (0)

#define AUX &svars->t[t]
#define DECL_SVARS \
	int t; \
	sync_vars_t *svars
#define INIT_SVARS(aux) \
	t = *(int *)aux; \
	svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))
#define DECL_INIT_SVARS(aux) \
	int t = *(int *)aux; \
	sync_vars_t *svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))

/* operation dependencies:
   select(S): -
   find_old(S): select(S)
   select(M): find_old(S) | -
   find_old(M): select(M)
   new(M), new(S), flags(M): find_old(M) & find_old(S)
   flags(S): count(new(S))
   find_new(x): new(x)
   trash(x): flags(x)
   close(x): trash(x) & find_new(x) // with expunge
   cleanup: close(M) & close(S)
*/

#define ST_SENT_FIND_OLD   (1<<0)
#define ST_SENT_NEW        (1<<1)
#define ST_SENT_FIND_NEW   (1<<2)
#define ST_SENT_FLAGS      (1<<3)
#define ST_SENT_TRASH      (1<<4)
#define ST_CLOSED          (1<<5)
#define ST_SENT_CANCEL     (1<<6)
#define ST_CANCELED        (1<<7)
#define ST_SELECTED        (1<<8)

#define ST_DID_EXPUNGE     (1<<16)


typedef struct copy_vars {
	void (*cb)( int sts, int uid, struct copy_vars *vars );
	void *aux;
	sync_rec_t *srec; /* also ->tuid */
	message_t *msg;
	msg_data_t data;
} copy_vars_t;

static void msg_fetched( int sts, void *aux );

static int
copy_msg( copy_vars_t *vars )
{
	DECL_INIT_SVARS(vars->aux);

	t ^= 1;
	vars->data.flags = vars->msg->flags;
	DRIVER_CALL_RET(fetch_msg( svars->ctx[t], vars->msg, &vars->data, msg_fetched, vars ));
}

static void msg_stored( int sts, int uid, void *aux );

static void
msg_fetched( int sts, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;
	char *fmap, *buf;
	int i, len, extra, scr, tcr, lcrs, hcrs, bcrs, lines;
	int start, sbreak = 0, ebreak = 0;
	char c;

	switch (sts) {
	case DRV_OK:
		INIT_SVARS(vars->aux);
		if (check_cancel( svars )) {
			free( vars->data.data );
			vars->cb( SYNC_CANCELED, 0, vars );
			return;
		}

		vars->msg->flags = vars->data.flags;

		scr = (svars->drv[1-t]->flags / DRV_CRLF) & 1;
		tcr = (svars->drv[t]->flags / DRV_CRLF) & 1;
		if (vars->srec || scr != tcr) {
			fmap = vars->data.data;
			len = vars->data.len;
			extra = lines = hcrs = bcrs = i = 0;
			if (vars->srec) {
			  nloop:
				start = i;
				lcrs = 0;
				while (i < len) {
					c = fmap[i++];
					if (c == '\r')
						lcrs++;
					else if (c == '\n') {
						if (!memcmp( fmap + start, "X-TUID: ", 8 )) {
							extra = (sbreak = start) - (ebreak = i);
							goto oke;
						}
						lines++;
						hcrs += lcrs;
						if (i - lcrs - 1 == start) {
							sbreak = ebreak = start;
							goto oke;
						}
						goto nloop;
					}
				}
				/* invalid message */
				warn( "Warning: message %d from %s has incomplete header.\n",
				      vars->msg->uid, str_ms[1-t] );
				free( fmap );
				vars->cb( SYNC_NOGOOD, 0, vars );
				return;
			  oke:
				extra += 8 + TUIDL + 1 + (tcr && (!scr || hcrs));
			}
			if (tcr != scr) {
				for (; i < len; i++) {
					c = fmap[i];
					if (c == '\r')
						bcrs++;
					else if (c == '\n')
						lines++;
				}
				extra -= hcrs + bcrs;
				if (tcr)
					extra += lines;
			}

			vars->data.len = len + extra;
			buf = vars->data.data = nfmalloc( vars->data.len );
			i = 0;
			if (vars->srec) {
				if (tcr != scr) {
					if (tcr) {
						for (; i < sbreak; i++)
							if ((c = fmap[i]) != '\r') {
								if (c == '\n')
									*buf++ = '\r';
								*buf++ = c;
							}
					} else {
						for (; i < sbreak; i++)
							if ((c = fmap[i]) != '\r')
								*buf++ = c;
					}
				} else {
					memcpy( buf, fmap, sbreak );
					buf += sbreak;
				}

				memcpy( buf, "X-TUID: ", 8 );
				buf += 8;
				memcpy( buf, vars->srec->tuid, TUIDL );
				buf += TUIDL;
				if (tcr && (!scr || hcrs))
					*buf++ = '\r';
				*buf++ = '\n';
				i = ebreak;
			}
			if (tcr != scr) {
				if (tcr) {
					for (; i < len; i++)
						if ((c = fmap[i]) != '\r') {
							if (c == '\n')
								*buf++ = '\r';
							*buf++ = c;
						}
				} else {
					for (; i < len; i++)
						if ((c = fmap[i]) != '\r')
							*buf++ = c;
				}
			} else
				memcpy( buf, fmap + i, len - i );

			free( fmap );
		}

		svars->drv[t]->store_msg( svars->ctx[t], &vars->data, !vars->srec, msg_stored, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}

static void
msg_stored( int sts, int uid, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;

	switch (sts) {
	case DRV_OK:
		vars->cb( SYNC_OK, uid, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		INIT_SVARS(vars->aux);
		(void)svars;
		warn( "Warning: %s refuses to store message %d from %s.\n",
		      str_ms[t], vars->msg->uid, str_ms[1-t] );
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}


static void
stats( sync_vars_t *svars )
{
	char buf[2][64];
	char *cs;
	int t, l;
	static int cols = -1;

	if (cols < 0 && (!(cs = getenv( "COLUMNS" )) || !(cols = atoi( cs ) / 2)))
		cols = 36;
	if (!(DFlags & QUIET)) {
		for (t = 0; t < 2; t++) {
			l = sprintf( buf[t], "?%d/%d +%d/%d *%d/%d #%d/%d",
			             svars->find_old_done[t] + svars->find_new_done[t],
			             svars->find_old_total[t] + svars->find_new_total[t],
			             svars->new_done[t], svars->new_total[t],
			             svars->flags_done[t], svars->flags_total[t],
			             svars->trash_done[t], svars->trash_total[t] );
			if (l > cols)
				buf[t][cols - 1] = '~';
		}
		infon( "\rM: %.*s  S: %.*s", cols, buf[0], cols, buf[1] );
	}
}


static void sync_bail( sync_vars_t *svars );
static void sync_bail1( sync_vars_t *svars );
static void sync_bail2( sync_vars_t *svars );
static void cancel_done( void *aux );

static void
cancel_sync( sync_vars_t *svars )
{
	int t;

	for (t = 0; t < 2; t++) {
		int other_state = svars->state[1-t];
		if (svars->ret & SYNC_BAD(t)) {
			cancel_done( AUX );
		} else if (!(svars->state[t] & ST_SENT_CANCEL)) {
			/* ignore subsequent failures from in-flight commands */
			svars->state[t] |= ST_SENT_CANCEL;
			svars->drv[t]->cancel( svars->ctx[t], cancel_done, AUX );
		}
		if (other_state & ST_CANCELED)
			break;
	}
}

static void
cancel_done( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->state[t] |= ST_CANCELED;
	if (svars->state[1-t] & ST_CANCELED) {
		if (svars->lfd) {
			Fclose( svars->nfp );
			Fclose( svars->jfp );
			sync_bail( svars );
		} else {
			sync_bail2( svars );
		}
	}
}

static void
store_bad( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->drv[t]->cancel_store( svars->ctx[t] );
	svars->ret |= SYNC_BAD(t);
	cancel_sync( svars );
}

static int
deref_check_cancel( sync_vars_t *svars )
{
	if (sync_deref( svars ))
		return -1;
	return check_cancel( svars );
}

static int
check_cancel( sync_vars_t *svars )
{
	return (svars->state[M] | svars->state[S]) & (ST_SENT_CANCEL | ST_CANCELED);
}

static int
check_ret( int sts, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_CANCELED)
		return 1;
	INIT_SVARS(aux);
	if (sts == DRV_BOX_BAD) {
		svars->ret |= SYNC_FAIL;
		cancel_sync( svars );
		return 1;
	}
	return check_cancel( svars );
}

#define SVARS_CHECK_RET \
	DECL_SVARS; \
	if (check_ret( sts, aux )) \
		return; \
	INIT_SVARS(aux)

#define SVARS_CHECK_RET_VARS(type) \
	type *vars = (type *)aux; \
	DECL_SVARS; \
	if (check_ret( sts, vars->aux )) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

#define SVARS_CHECK_CANCEL_RET \
	DECL_SVARS; \
	if (sts == SYNC_CANCELED) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

static char *
clean_strdup( const char *s )
{
	char *cs;
	int i;

	cs = nfstrdup( s );
	for (i = 0; cs[i]; i++)
		if (cs[i] == '/')
			cs[i] = '!';
	return cs;
}


#define JOURNAL_VERSION "2"

static void box_selected( int sts, void *aux );

void
sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan,
            void (*cb)( int sts, void *aux ), void *aux )
{
	sync_vars_t *svars;
	int t;

	svars = nfcalloc( sizeof(*svars) );
	svars->t[1] = 1;
	svars->ref_count = 1;
	svars->cb = cb;
	svars->aux = aux;
	svars->ctx[0] = ctx[0];
	svars->ctx[1] = ctx[1];
	svars->chan = chan;
	svars->uidval[0] = svars->uidval[1] = -1;
	svars->srecadd = &svars->srecs;

	for (t = 0; t < 2; t++) {
		ctx[t]->name =
			(!names[t] || (ctx[t]->conf->map_inbox && !strcmp( ctx[t]->conf->map_inbox, names[t] ))) ?
				"INBOX" : names[t];
		ctx[t]->uidvalidity = -1;
		set_bad_callback( ctx[t], store_bad, AUX );
		svars->drv[t] = ctx[t]->conf->driver;
		info( "Selecting %s %s...\n", str_ms[t], ctx[t]->name );
		DRIVER_CALL(select( ctx[t], (chan->ops[t] & OP_CREATE) != 0, box_selected, AUX ));
	}
}

static int load_box( sync_vars_t *svars, int t, int minwuid, int *mexcs, int nmexcs );

static void
box_selected( int sts, void *aux )
{
	DECL_SVARS;
	sync_rec_t *srec, *nsrec;
	char *s, *cmname, *csname;
	store_t *ctx[2];
	channel_conf_t *chan;
	FILE *jfp;
	int opts[2], line, t1, t2, t3;
	struct stat st;
	struct flock lck;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[64];

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	ctx[0] = svars->ctx[0];
	ctx[1] = svars->ctx[1];
	svars->state[t] |= ST_SELECTED;
	if (!(svars->state[1-t] & ST_SELECTED))
		return;

	chan = svars->chan;
	if (!strcmp( chan->sync_state ? chan->sync_state : global_sync_state, "*" )) {
		if (!ctx[S]->path) {
			error( "Error: store '%s' does not support in-box sync state\n", chan->stores[S]->name );
		  sbail:
			svars->ret = SYNC_BAD(S);
			sync_bail2( svars );
			return;
		}
		nfasprintf( &svars->dname, "%s/." EXE "state", ctx[S]->path );
	} else {
		csname = clean_strdup( ctx[S]->name );
		if (chan->sync_state)
			nfasprintf( &svars->dname, "%s%s", chan->sync_state, csname );
		else {
			cmname = clean_strdup( ctx[M]->name );
			nfasprintf( &svars->dname, "%s:%s:%s_:%s:%s", global_sync_state,
			            chan->stores[M]->name, cmname, chan->stores[S]->name, csname );
			free( cmname );
		}
		free( csname );
		if (!(s = strrchr( svars->dname, '/' ))) {
			error( "Error: invalid SyncState '%s'\n", svars->dname );
			goto sbail;
		}
		*s = 0;
		if (mkdir( svars->dname, 0700 ) && errno != EEXIST) {
			error( "Error: cannot create SyncState directory '%s': %s\n", svars->dname, strerror(errno) );
			goto sbail;
		}
		*s = '/';
	}
	nfasprintf( &svars->jname, "%s.journal", svars->dname );
	nfasprintf( &svars->nname, "%s.new", svars->dname );
	nfasprintf( &svars->lname, "%s.lock", svars->dname );
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	if ((svars->lfd = open( svars->lname, O_WRONLY|O_CREAT, 0666 )) < 0) {
		error( "Error: cannot create lock file %s: %s\n", svars->lname, strerror(errno) );
		svars->ret = SYNC_FAIL;
		sync_bail2( svars );
		return;
	}
	if (fcntl( svars->lfd, F_SETLK, &lck )) {
		error( "Error: channel :%s:%s-:%s:%s is locked\n",
		         chan->stores[M]->name, ctx[M]->name, chan->stores[S]->name, ctx[S]->name );
		svars->ret = SYNC_FAIL;
		sync_bail1( svars );
		return;
	}
	if ((jfp = fopen( svars->dname, "r" ))) {
		debug( "reading sync state %s ...\n", svars->dname );
		if (!fgets( buf, sizeof(buf), jfp ) || !(t = strlen( buf )) || buf[t - 1] != '\n') {
			error( "Error: incomplete sync state header in %s\n", svars->dname );
		  jbail:
			fclose( jfp );
		  bail:
			svars->ret = SYNC_FAIL;
			sync_bail( svars );
			return;
		}
		if (sscanf( buf, "%d:%d %d:%d:%d", &svars->uidval[M], &svars->maxuid[M], &svars->uidval[S], &svars->smaxxuid, &svars->maxuid[S]) != 5) {
			error( "Error: invalid sync state header in %s\n", svars->dname );
			goto jbail;
		}
		line = 1;
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			fbuf[0] = 0;
			if (sscanf( buf, "%d %d %15s", &t1, &t2, fbuf ) < 2) {
				error( "Error: invalid sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			srec = nfmalloc( sizeof(*srec) );
			srec->uid[M] = t1;
			srec->uid[S] = t2;
			s = fbuf;
			if (*s == 'X') {
				s++;
				srec->status = S_EXPIRE | S_EXPIRED;
			} else
				srec->status = 0;
			srec->flags = parse_flags( s );
			debug( "  entry (%d,%d,%u,%s)\n", srec->uid[M], srec->uid[S], srec->flags, srec->status & S_EXPIRED ? "X" : "" );
			srec->msg[M] = srec->msg[S] = 0;
			srec->tuid[0] = 0;
			srec->next = 0;
			*svars->srecadd = srec;
			svars->srecadd = &srec->next;
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			error( "Error: cannot read sync state %s\n", svars->dname );
			goto bail;
		}
	}
	line = 0;
	if ((jfp = fopen( svars->jname, "r" ))) {
		if (!stat( svars->nname, &st ) && fgets( buf, sizeof(buf), jfp )) {
			debug( "recovering journal ...\n" );
			if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
				error( "Error: incomplete journal header in %s\n", svars->jname );
				goto jbail;
			}
			if (memcmp( buf, JOURNAL_VERSION "\n", strlen(JOURNAL_VERSION) + 1 )) {
				error( "Error: incompatible journal version "
				                 "(got %.*s, expected " JOURNAL_VERSION ")\n", t - 1, buf );
				goto jbail;
			}
			srec = 0;
			line = 1;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (!(t = strlen( buf )) || buf[t - 1] != '\n') {
					error( "Error: incomplete journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				if (buf[0] == '#' ?
				      (t3 = 0, (sscanf( buf + 2, "%d %d %n", &t1, &t2, &t3 ) < 2) || !t3 || (t - t3 != TUIDL + 3)) :
				      buf[0] == '(' || buf[0] == ')' ?
				        (sscanf( buf + 2, "%d", &t1 ) != 1) :
				        buf[0] == '+' || buf[0] == '&' || buf[0] == '-' || buf[0] == '|' || buf[0] == '/' || buf[0] == '\\' ?
				          (sscanf( buf + 2, "%d %d", &t1, &t2 ) != 2) :
				          (sscanf( buf + 2, "%d %d %d", &t1, &t2, &t3 ) != 3))
				{
					error( "Error: malformed journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				if (buf[0] == '(')
					svars->maxuid[M] = t1;
				else if (buf[0] == ')')
					svars->maxuid[S] = t1;
				else if (buf[0] == '|') {
					svars->uidval[M] = t1;
					svars->uidval[S] = t2;
				} else if (buf[0] == '+') {
					srec = nfmalloc( sizeof(*srec) );
					srec->uid[M] = t1;
					srec->uid[S] = t2;
					debug( "  new entry(%d,%d)\n", t1, t2 );
					srec->msg[M] = srec->msg[S] = 0;
					srec->status = 0;
					srec->flags = 0;
					srec->tuid[0] = 0;
					srec->next = 0;
					*svars->srecadd = srec;
					svars->srecadd = &srec->next;
				} else {
					for (nsrec = srec; srec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					for (srec = svars->srecs; srec != nsrec; srec = srec->next)
						if (srec->uid[M] == t1 && srec->uid[S] == t2)
							goto syncfnd;
					error( "Error: journal entry at %s:%d refers to non-existing sync state entry\n", svars->jname, line );
					goto jbail;
				  syncfnd:
					debugn( "  entry(%d,%d,%u) ", srec->uid[M], srec->uid[S], srec->flags );
					switch (buf[0]) {
					case '-':
						debug( "killed\n" );
						srec->status = S_DEAD;
						break;
					case '#':
						debug( "TUID now %." stringify(TUIDL) "s\n", buf + t3 + 2 );
						memcpy( srec->tuid, buf + t3 + 2, TUIDL );
						break;
					case '&':
						debug( "TUID %." stringify(TUIDL) "s lost\n", srec->tuid );
						srec->flags = 0;
						srec->tuid[0] = 0;
						break;
					case '<':
						debug( "master now %d\n", t3 );
						srec->uid[M] = t3;
						srec->tuid[0] = 0;
						break;
					case '>':
						debug( "slave now %d\n", t3 );
						srec->uid[S] = t3;
						srec->tuid[0] = 0;
						break;
					case '*':
						debug( "flags now %d\n", t3 );
						srec->flags = t3;
						break;
					case '~':
						debug( "expire now %d\n", t3 );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '\\':
						t3 = (srec->status & S_EXPIRED);
						debug( "expire back to %d\n", t3 / S_EXPIRED );
						if (t3)
							srec->status |= S_EXPIRE;
						else
							srec->status &= ~S_EXPIRE;
						break;
					case '/':
						t3 = (srec->status & S_EXPIRE);
						debug( "expired now %d\n", t3 / S_EXPIRE );
						if (t3) {
							if (svars->smaxxuid < srec->uid[S])
								svars->smaxxuid = srec->uid[S];
							srec->status |= S_EXPIRED;
						} else
							srec->status &= ~S_EXPIRED;
						break;
					default:
						error( "Error: unrecognized journal entry at %s:%d\n", svars->jname, line );
						goto jbail;
					}
				}
			}
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			error( "Error: cannot read journal %s\n", svars->jname );
			goto bail;
		}
	}

	t1 = 0;
	for (t = 0; t < 2; t++)
		if (svars->uidval[t] >= 0 && svars->uidval[t] != ctx[t]->uidvalidity) {
			error( "Error: UIDVALIDITY of %s changed (got %d, expected %d)\n",
			       str_ms[t], ctx[t]->uidvalidity, svars->uidval[t] );
			t1++;
		}
	if (t1)
		goto bail;

	if (!(svars->nfp = fopen( svars->nname, "w" ))) {
		error( "Error: cannot write new sync state %s\n", svars->nname );
		goto bail;
	}
	if (!(svars->jfp = fopen( svars->jname, "a" ))) {
		error( "Error: cannot write journal %s\n", svars->jname );
		fclose( svars->nfp );
		goto bail;
	}
	setlinebuf( svars->jfp );
	if (!line)
		Fprintf( svars->jfp, JOURNAL_VERSION "\n" );

	opts[M] = opts[S] = 0;
	for (t = 0; t < 2; t++) {
		if (chan->ops[t] & (OP_DELETE|OP_FLAGS)) {
			opts[t] |= OPEN_SETFLAGS;
			opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_FLAGS)
				opts[1-t] |= OPEN_FLAGS;
		}
		if (chan->ops[t] & (OP_NEW|OP_RENEW)) {
			opts[t] |= OPEN_APPEND;
			if (chan->ops[t] & OP_RENEW)
				opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_NEW)
				opts[1-t] |= OPEN_NEW;
			if (chan->ops[t] & OP_EXPUNGE)
				opts[1-t] |= OPEN_FLAGS;
			if (chan->stores[t]->max_size)
				opts[1-t] |= OPEN_SIZE;
		}
		if (chan->ops[t] & OP_EXPUNGE) {
			opts[t] |= OPEN_EXPUNGE;
			if (chan->stores[t]->trash) {
				if (!chan->stores[t]->trash_only_new)
					opts[t] |= OPEN_OLD;
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
			} else if (chan->stores[1-t]->trash && chan->stores[1-t]->trash_remote_new)
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
		}
	}
	if ((chan->ops[S] & (OP_NEW|OP_RENEW)) && chan->max_messages)
		opts[S] |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	if (line)
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if ((mvBit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)
				opts[S] |= OPEN_OLD|OPEN_FLAGS;
			if (srec->tuid[0]) {
				if (srec->uid[M] == -2)
					opts[M] |= OPEN_OLD|OPEN_FIND;
				else if (srec->uid[S] == -2)
					opts[S] |= OPEN_OLD|OPEN_FIND;
			}
		}
	svars->drv[M]->prepare_opts( ctx[M], opts[M] );
	svars->drv[S]->prepare_opts( ctx[S], opts[S] );

	svars->find = line != 0;
	if (!svars->smaxxuid && load_box( svars, M, (ctx[M]->opts & OPEN_OLD) ? 1 : INT_MAX, 0, 0 ))
		return;
	load_box( svars, S, (ctx[S]->opts & OPEN_OLD) ? 1 : INT_MAX, 0, 0 );
}

static void box_loaded( int sts, void *aux );

static int
load_box( sync_vars_t *svars, int t, int minwuid, int *mexcs, int nmexcs )
{
	sync_rec_t *srec;
	int maxwuid;

	if (svars->ctx[t]->opts & OPEN_NEW) {
		if (minwuid > svars->maxuid[t] + 1)
			minwuid = svars->maxuid[t] + 1;
		maxwuid = INT_MAX;
	} else if (svars->ctx[t]->opts & OPEN_OLD) {
		maxwuid = 0;
		for (srec = svars->srecs; srec; srec = srec->next)
			if (!(srec->status & S_DEAD) && srec->uid[t] > maxwuid)
				maxwuid = srec->uid[t];
	} else
		maxwuid = 0;
	info( "Loading %s...\n", str_ms[t] );
	debug( maxwuid == INT_MAX ? "loading %s [%d,inf]\n" : "loading %s [%d,%d]\n", str_ms[t], minwuid, maxwuid );
	DRIVER_CALL_RET(load( svars->ctx[t], minwuid, maxwuid, mexcs, nmexcs, box_loaded, AUX ));
}

typedef struct {
	void *aux;
	sync_rec_t *srec;
} find_vars_t;

static void msg_found_sel( int sts, int uid, void *aux );
static void msgs_found_sel( sync_vars_t *svars, int t );

static void
box_loaded( int sts, void *aux )
{
	find_vars_t *fv;
	sync_rec_t *srec;

	SVARS_CHECK_RET;
	info( "%s: %d messages, %d recent\n", str_ms[t], svars->ctx[t]->count, svars->ctx[t]->recent );

	if (svars->find) {
		/*
		 * Alternatively, the TUIDs could be fetched into the messages and
		 * looked up here. This would make the search faster (probably) and
		 * save roundtrips. On the downside, quite some additional data would
		 * have to be fetched for every message and the IMAP driver would be
		 * more complicated. This is a corner case anyway, so why bother.
		 */
		debug( "finding previously copied messages\n" );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == -2 && srec->tuid[0]) {
				debug( "  pair(%d,%d): lookup %s, TUID %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], str_ms[t], srec->tuid );
				svars->find_old_total[t]++;
				stats( svars );
				fv = nfmalloc( sizeof(*fv) );
				fv->aux = AUX;
				fv->srec = srec;
				DRIVER_CALL(find_msg( svars->ctx[t], srec->tuid, msg_found_sel, fv ));
			}
		}
	}
	svars->state[t] |= ST_SENT_FIND_OLD;
	msgs_found_sel( svars, t );
}

static void
msg_found_sel( int sts, int uid, void *aux )
{
	SVARS_CHECK_RET_VARS(find_vars_t);
	switch (sts) {
	case DRV_OK:
		debug( "  -> new UID %d\n", uid );
		Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], vars->srec->uid[M], vars->srec->uid[S], uid );
		vars->srec->uid[t] = uid;
		vars->srec->tuid[0] = 0;
		break;
	default:
		debug( "  -> TUID lost\n" );
		Fprintf( svars->jfp, "& %d %d\n", vars->srec->uid[M], vars->srec->uid[S] );
		vars->srec->flags = 0;
		vars->srec->tuid[0] = 0;
		break;
	}
	free( vars );
	svars->find_old_done[t]++;
	stats( svars );
	msgs_found_sel( svars, t );
}

typedef struct {
	void *aux;
	sync_rec_t *srec;
	int aflags, dflags;
} flag_vars_t;

static void flags_set_del( int sts, void *aux );
static void flags_set_sync( int sts, void *aux );
static void flags_set_sync_p2( sync_vars_t *svars, sync_rec_t *srec, int t );
static int msgs_flags_set( sync_vars_t *svars, int t );
static void msg_copied( int sts, int uid, copy_vars_t *vars );
static void msg_copied_p2( sync_vars_t *svars, sync_rec_t *srec, int t, message_t *tmsg, int uid );
static void msgs_copied( sync_vars_t *svars, int t );

static void
msgs_found_sel( sync_vars_t *svars, int t )
{
	sync_rec_t *srec, *nsrec = 0;
	message_t *tmsg;
	copy_vars_t *cv;
	flag_vars_t *fv;
	const char *diag;
	int uid, minwuid, *mexcs, nmexcs, rmexcs, no[2], del[2], todel, t1, t2;
	int sflags, nflags, aflags, dflags, nex;
	char fbuf[16]; /* enlarge when support for keywords is added */

	if (!(svars->state[t] & ST_SENT_FIND_OLD) || svars->find_old_done[t] < svars->find_old_total[t])
		return;

	/*
	 * Mapping tmsg -> srec (this variant) is dog slow for new messages.
	 * Mapping srec -> tmsg is dog slow for deleted messages.
	 * One solution would be using binary search on an index array.
	 * msgs are already sorted by UID, srecs would have to be sorted by uid[t].
	 */
	debug( "matching messages against sync records\n" );
	for (tmsg = svars->ctx[t]->msgs; tmsg; tmsg = tmsg->next) {
		uid = tmsg->uid;
		if (DFlags & DEBUG) {
			make_flags( tmsg->flags, fbuf );
			printf( svars->ctx[t]->opts & OPEN_SIZE ? "  message %5d, %-4s, %6lu: " : "  message %5d, %-4s: ", uid, fbuf, tmsg->size );
		}
		for (srec = nsrec; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == uid) {
				diag = srec == nsrec ? "adjacently" : "after gap";
				goto found;
			}
		}
		for (srec = svars->srecs; srec != nsrec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[t] == uid) {
				diag = "after reset";
				goto found;
			}
		}
		tmsg->srec = 0;
		debug( "new\n" );
		continue;
	  found:
		tmsg->srec = srec;
		srec->msg[t] = tmsg;
		nsrec = srec->next;
		debug( "pairs %5d %s\n", srec->uid[1-t], diag );
	}

	if ((t == S) && svars->smaxxuid) {
		debug( "preparing master selection - max expired slave uid is %d\n", svars->smaxxuid );
		mexcs = 0;
		nmexcs = rmexcs = 0;
		minwuid = INT_MAX;
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXPIRED) {
				if (!srec->uid[S] || ((svars->ctx[S]->opts & OPEN_OLD) && !srec->msg[S])) {
					srec->status |= S_EXP_S;
					continue;
				}
			} else {
				if (svars->smaxxuid >= srec->uid[S])
					continue;
			}
			if (minwuid > srec->uid[M])
				minwuid = srec->uid[M];
		}
		debug( "  min non-orphaned master uid is %d\n", minwuid );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->status & S_EXP_S) {
				if (minwuid > srec->uid[M] && svars->maxuid[M] >= srec->uid[M]) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S]) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (minwuid > srec->uid[M]) {
				if (srec->uid[S] < 0) {
					if (svars->maxuid[M] >= srec->uid[M]) {
						debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
						srec->status = S_DEAD;
						Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
					}
				} else if (srec->uid[M] > 0 && srec->uid[S] && (svars->ctx[M]->opts & OPEN_OLD) &&
				           (!(svars->ctx[M]->opts & OPEN_NEW) || svars->maxuid[M] >= srec->uid[M])) {
					if (nmexcs == rmexcs) {
						rmexcs = rmexcs * 2 + 100;
						mexcs = nfrealloc( mexcs, rmexcs * sizeof(int) );
					}
					mexcs[nmexcs++] = srec->uid[M];
				}
			}
		}
		debugn( "  exception list is:" );
		for (t = 0; t < nmexcs; t++)
			debugn( " %d", mexcs[t] );
		debug( "\n" );
		load_box( svars, M, minwuid, mexcs, nmexcs );
		return;
	}

	if (!(svars->state[1-t] & ST_SENT_FIND_OLD) || svars->find_old_done[1-t] < svars->find_old_total[1-t])
		return;

	if (svars->uidval[M] < 0 || svars->uidval[S] < 0) {
		svars->uidval[M] = svars->ctx[M]->uidvalidity;
		svars->uidval[S] = svars->ctx[S]->uidvalidity;
		Fprintf( svars->jfp, "| %d %d\n", svars->uidval[M], svars->uidval[S] );
	}

	info( "Synchronizing...\n" );

	debug( "synchronizing new entries\n" );
	svars->osrecadd = svars->srecadd;
	for (t = 0; t < 2; t++) {
		for (tmsg = svars->ctx[1-t]->msgs; tmsg; tmsg = tmsg->next)
			if (tmsg->srec ? tmsg->srec->uid[t] < 0 && (tmsg->srec->uid[t] == -1 ? (svars->chan->ops[t] & OP_RENEW) : (svars->chan->ops[t] & OP_NEW)) : (svars->chan->ops[t] & OP_NEW)) {
				debug( "new message %d on %s\n", tmsg->uid, str_ms[1-t] );
				if ((svars->chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED))
					debug( "  -> not %sing - would be expunged anyway\n", str_hl[t] );
				else {
					if (tmsg->srec) {
						srec = tmsg->srec;
						srec->status |= S_DONE;
						debug( "  -> pair(%d,%d) exists\n", srec->uid[M], srec->uid[S] );
					} else {
						srec = nfmalloc( sizeof(*srec) );
						srec->next = 0;
						*svars->srecadd = srec;
						svars->srecadd = &srec->next;
						srec->status = S_DONE;
						srec->flags = 0;
						srec->tuid[0] = 0;
						srec->uid[1-t] = tmsg->uid;
						srec->uid[t] = -2;
						Fprintf( svars->jfp, "+ %d %d\n", srec->uid[M], srec->uid[S] );
						debug( "  -> pair(%d,%d) created\n", srec->uid[M], srec->uid[S] );
					}
					if ((tmsg->flags & F_FLAGGED) || !svars->chan->stores[t]->max_size || tmsg->size <= svars->chan->stores[t]->max_size) {
						if (tmsg->flags) {
							srec->flags = tmsg->flags;
							Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], srec->flags );
							debug( "  -> updated flags to %u\n", tmsg->flags );
						}
						for (t1 = 0; t1 < TUIDL; t1++) {
							t2 = arc4_getbyte() & 0x3f;
							srec->tuid[t1] = t2 < 26 ? t2 + 'A' : t2 < 52 ? t2 + 'a' - 26 : t2 < 62 ? t2 + '0' - 52 : t2 == 62 ? '+' : '/';
						}
						svars->new_total[t]++;
						stats( svars );
						cv = nfmalloc( sizeof(*cv) );
						cv->cb = msg_copied;
						cv->aux = AUX;
						cv->srec = srec;
						cv->msg = tmsg;
						Fprintf( svars->jfp, "# %d %d %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], srec->tuid );
						debug( "  -> %sing message, TUID %." stringify(TUIDL) "s\n", str_hl[t], srec->tuid );
						if (copy_msg( cv ))
							return;
					} else {
						if (tmsg->srec) {
							debug( "  -> not %sing - still too big\n", str_hl[t] );
							continue;
						}
						debug( "  -> not %sing - too big\n", str_hl[t] );
						msg_copied_p2( svars, srec, t, tmsg, -1 );
					}
				}
			}
		svars->state[t] |= ST_SENT_NEW;
		msgs_copied( svars, t );
	}

	debug( "synchronizing old entries\n" );
	for (srec = svars->srecs; srec != *svars->osrecadd; srec = srec->next) {
		if (srec->status & (S_DEAD|S_DONE))
			continue;
		debug( "pair (%d,%d)\n", srec->uid[M], srec->uid[S] );
		no[M] = !srec->msg[M] && (svars->ctx[M]->opts & OPEN_OLD);
		no[S] = !srec->msg[S] && (svars->ctx[S]->opts & OPEN_OLD);
		if (no[M] && no[S]) {
			debug( "  vanished\n" );
			/* d.1) d.5) d.6) d.10) d.11) */
			srec->status = S_DEAD;
			Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
		} else {
			del[M] = no[M] && (srec->uid[M] > 0);
			del[S] = no[S] && (srec->uid[S] > 0);

			for (t = 0; t < 2; t++) {
				srec->aflags[t] = srec->dflags[t] = 0;
				if (srec->msg[t] && (srec->msg[t]->flags & F_DELETED))
					srec->status |= S_DEL(t);
				/* excludes (push) c.3) d.2) d.3) d.4) / (pull) b.3) d.7) d.8) d.9) */
				if (!srec->uid[t]) {
					/* b.1) / c.1) */
					debug( "  no more %s\n", str_ms[t] );
				} else if (del[1-t]) {
					/* c.4) d.9) / b.4) d.4) */
					if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS) && srec->msg[t]->flags != srec->flags)
						info( "Info: conflicting changes in (%d,%d)\n", srec->uid[M], srec->uid[S] );
					if (svars->chan->ops[t] & OP_DELETE) {
						debug( "  %sing delete\n", str_hl[t] );
						svars->flags_total[t]++;
						stats( svars );
						fv = nfmalloc( sizeof(*fv) );
						fv->aux = AUX;
						fv->srec = srec;
						DRIVER_CALL(set_flags( svars->ctx[t], srec->msg[t], srec->uid[t], F_DELETED, 0, flags_set_del, fv ));
					} else
						debug( "  not %sing delete\n", str_hl[t] );
				} else if (!srec->msg[1-t])
					/* c.1) c.2) d.7) d.8) / b.1) b.2) d.2) d.3) */
					;
				else if (srec->uid[t] < 0)
					/* b.2) / c.2) */
					; /* handled as new messages (sort of) */
				else if (!del[t]) {
					/* a) & b.3) / c.3) */
					if (svars->chan->ops[t] & OP_FLAGS) {
						sflags = srec->msg[1-t]->flags;
						if ((srec->status & (S_EXPIRE|S_EXPIRED)) && !t)
							sflags &= ~F_DELETED;
						srec->aflags[t] = sflags & ~srec->flags;
						srec->dflags[t] = ~sflags & srec->flags;
						if (DFlags & DEBUG) {
							char afbuf[16], dfbuf[16]; /* enlarge when support for keywords is added */
							make_flags( srec->aflags[t], afbuf );
							make_flags( srec->dflags[t], dfbuf );
							debug( "  %sing flags: +%s -%s\n", str_hl[t], afbuf, dfbuf );
						}
					} else
						debug( "  not %sing flags\n", str_hl[t] );
				} /* else b.4) / c.4) */
			}
		}
	}

	if ((svars->chan->ops[S] & (OP_NEW|OP_RENEW|OP_FLAGS)) && svars->chan->max_messages) {
		/* Flagged and not yet synced messages older than the first not
		 * expired message are not counted. */
		todel = svars->ctx[S]->count + svars->new_total[S] - svars->chan->max_messages;
		debug( "scheduling %d excess messages for expiration\n", todel );
		for (tmsg = svars->ctx[S]->msgs; tmsg && todel > 0; tmsg = tmsg->next)
			if (!(tmsg->status & M_DEAD) && (srec = tmsg->srec) &&
			    ((tmsg->flags | srec->aflags[S]) & ~srec->dflags[S] & F_DELETED) &&
			    !(srec->status & (S_EXPIRE|S_EXPIRED)))
				todel--;
		debug( "%d non-deleted excess messages\n", todel );
		for (tmsg = svars->ctx[S]->msgs; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			if (!(srec = tmsg->srec) || srec->uid[M] <= 0)
				todel--;
			else {
				nflags = (tmsg->flags | srec->aflags[S]) & ~srec->dflags[S];
				if (!(nflags & F_DELETED) || (srec->status & (S_EXPIRE|S_EXPIRED))) {
					if (nflags & F_FLAGGED)
						todel--;
					else if ((!(tmsg->status & M_RECENT) || (tmsg->flags & F_SEEN)) &&
					         (todel > 0 ||
					          ((srec->status & (S_EXPIRE|S_EXPIRED)) == (S_EXPIRE|S_EXPIRED)) ||
					          ((srec->status & (S_EXPIRE|S_EXPIRED)) && (tmsg->flags & F_DELETED)))) {
						srec->status |= S_NEXPIRE;
						debug( "  pair(%d,%d)\n", srec->uid[M], srec->uid[S] );
						todel--;
					}
				}
			}
		}
		debug( "%d excess messages remain\n", todel );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if ((srec->status & (S_DEAD|S_DONE)) || !srec->msg[S])
				continue;
			nex = (srec->status / S_NEXPIRE) & 1;
			if (nex != ((srec->status / S_EXPIRED) & 1)) {
				if (nex != ((srec->status / S_EXPIRE) & 1)) {
					Fprintf( svars->jfp, "~ %d %d %d\n", srec->uid[M], srec->uid[S], nex );
					debug( "  pair(%d,%d): %d (pre)\n", srec->uid[M], srec->uid[S], nex );
					srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
				} else
					debug( "  pair(%d,%d): %d (pending)\n", srec->uid[M], srec->uid[S], nex );
			}
		}
	}

	debug( "synchronizing flags\n" );
	for (srec = svars->srecs; srec != *svars->osrecadd; srec = srec->next) {
		if (srec->status & (S_DEAD|S_DONE))
			continue;
		for (t = 0; t < 2; t++) {
			aflags = srec->aflags[t];
			dflags = srec->dflags[t];
			if ((t == S) && ((mvBit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)) {
				if (srec->status & S_NEXPIRE)
					aflags |= F_DELETED;
				else
					dflags |= F_DELETED;
			}
			if ((svars->chan->ops[t] & OP_EXPUNGE) && (((srec->msg[t] ? srec->msg[t]->flags : 0) | aflags) & ~dflags & F_DELETED) &&
			    (!svars->ctx[t]->conf->trash || svars->ctx[t]->conf->trash_only_new))
			{
				srec->aflags[t] &= F_DELETED;
				aflags &= F_DELETED;
				srec->dflags[t] = dflags = 0;
			}
			if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS)) {
				aflags &= ~srec->msg[t]->flags;
				dflags &= srec->msg[t]->flags;
			}
			if (aflags | dflags) {
				svars->flags_total[t]++;
				stats( svars );
				fv = nfmalloc( sizeof(*fv) );
				fv->aux = AUX;
				fv->srec = srec;
				fv->aflags = aflags;
				fv->dflags = dflags;
				DRIVER_CALL(set_flags( svars->ctx[t], srec->msg[t], srec->uid[t], aflags, dflags, flags_set_sync, fv ));
			} else
				flags_set_sync_p2( svars, srec, t );
		}
	}
	for (t = 0; t < 2; t++) {
		svars->drv[t]->commit( svars->ctx[t] );
		svars->state[t] |= ST_SENT_FLAGS;
		if (msgs_flags_set( svars, t ))
			return;
	}
}

static void
msg_copied( int sts, int uid, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	switch (sts) {
	case SYNC_OK:
		msg_copied_p2( svars, vars->srec, t, vars->msg, uid );
		break;
	case SYNC_NOGOOD:
		debug( "  -> killing (%d,%d)\n", vars->srec->uid[M], vars->srec->uid[S] );
		vars->srec->status = S_DEAD;
		Fprintf( svars->jfp, "- %d %d\n", vars->srec->uid[M], vars->srec->uid[S] );
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	free( vars );
	svars->new_done[t]++;
	stats( svars );
	msgs_copied( svars, t );
}

static void
msg_copied_p2( sync_vars_t *svars, sync_rec_t *srec, int t, message_t *tmsg, int uid )
{
	if (srec->uid[t] != uid) {
		debug( "  -> new UID %d\n", uid );
		Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], srec->uid[M], srec->uid[S], uid );
		srec->uid[t] = uid;
		srec->tuid[0] = 0;
	}
	if (!tmsg->srec) {
		tmsg->srec = srec;
		if (svars->maxuid[1-t] < tmsg->uid) {
			svars->maxuid[1-t] = tmsg->uid;
			Fprintf( svars->jfp, "%c %d\n", ")("[t], tmsg->uid );
		}
	}
}

static void msg_found_new( int sts, int uid, void *aux );
static void sync_close( sync_vars_t *svars, int t );

static void
msgs_copied( sync_vars_t *svars, int t )
{
	sync_rec_t *srec;
	find_vars_t *fv;

	if (!(svars->state[t] & ST_SENT_NEW) || svars->new_done[t] < svars->new_total[t])
		return;

	debug( "finding just copied messages on %s\n", str_ms[t] );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		if (srec->tuid[0] && srec->uid[t] == -2) {
			debug( "  pair(%d,%d): lookup %s, TUID %." stringify(TUIDL) "s\n", srec->uid[M], srec->uid[S], str_ms[t], srec->tuid );
			svars->find_new_total[t]++;
			stats( svars );
			fv = nfmalloc( sizeof(*fv) );
			fv->aux = AUX;
			fv->srec = srec;
			DRIVER_CALL(find_msg( svars->ctx[t], srec->tuid, msg_found_new, fv ));
		}
	}
	svars->state[t] |= ST_SENT_FIND_NEW;
	sync_close( svars, t );
}

static void
msg_found_new( int sts, int uid, void *aux )
{
	SVARS_CHECK_RET_VARS(find_vars_t);
	switch (sts) {
	case DRV_OK:
		debug( "  -> new UID %d\n", uid );
		break;
	default:
		warn( "Warning: cannot find newly stored message %." stringify(TUIDL) "s on %s.\n", vars->srec->tuid, str_ms[t] );
		uid = 0;
		break;
	}
	Fprintf( svars->jfp, "%c %d %d %d\n", "<>"[t], vars->srec->uid[M], vars->srec->uid[S], uid );
	vars->srec->uid[t] = uid;
	vars->srec->tuid[0] = 0;
	free( vars );
	svars->find_new_done[t]++;
	stats( svars );
	sync_close( svars, t );
}

static void
flags_set_del( int sts, void *aux )
{
	SVARS_CHECK_RET_VARS(flag_vars_t);
	switch (sts) {
	case DRV_OK:
		vars->srec->status |= S_DEL(t);
		Fprintf( svars->jfp, "%c %d %d 0\n", "><"[t], vars->srec->uid[M], vars->srec->uid[S] );
		vars->srec->uid[1-t] = 0;
		break;
	}
	free( vars );
	svars->flags_done[t]++;
	stats( svars );
	msgs_flags_set( svars, t );
}

static void
flags_set_sync( int sts, void *aux )
{
	SVARS_CHECK_RET_VARS(flag_vars_t);
	switch (sts) {
	case DRV_OK:
		if (vars->aflags & F_DELETED)
			vars->srec->status |= S_DEL(t);
		else if (vars->dflags & F_DELETED)
			vars->srec->status &= ~S_DEL(t);
		flags_set_sync_p2( svars, vars->srec, t );
		break;
	}
	free( vars );
	svars->flags_done[t]++;
	stats( svars );
	msgs_flags_set( svars, t );
}

static void
flags_set_sync_p2( sync_vars_t *svars, sync_rec_t *srec, int t )
{
	int nflags, nex;

	nflags = (srec->flags | srec->aflags[t]) & ~srec->dflags[t];
	if (srec->flags != nflags) {
		debug( "  pair(%d,%d): updating flags (%u -> %u)\n", srec->uid[M], srec->uid[S], srec->flags, nflags );
		srec->flags = nflags;
		Fprintf( svars->jfp, "* %d %d %u\n", srec->uid[M], srec->uid[S], nflags );
	}
	if (t == S) {
		nex = (srec->status / S_NEXPIRE) & 1;
		if (nex != ((srec->status / S_EXPIRED) & 1)) {
			if (nex && (svars->smaxxuid < srec->uid[S]))
				svars->smaxxuid = srec->uid[S];
			Fprintf( svars->jfp, "/ %d %d\n", srec->uid[M], srec->uid[S] );
			debug( "  pair(%d,%d): expired %d (commit)\n", srec->uid[M], srec->uid[S], nex );
			srec->status = (srec->status & ~S_EXPIRED) | (nex * S_EXPIRED);
		} else if (nex != ((srec->status / S_EXPIRE) & 1)) {
			Fprintf( svars->jfp, "\\ %d %d\n", srec->uid[M], srec->uid[S] );
			debug( "  pair(%d,%d): expire %d (cancel)\n", srec->uid[M], srec->uid[S], nex );
			srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
		}
	}
}

static void msg_trashed( int sts, void *aux );
static void msg_rtrashed( int sts, int uid, copy_vars_t *vars );

static int
msgs_flags_set( sync_vars_t *svars, int t )
{
	message_t *tmsg;
	copy_vars_t *cv;

	if (!(svars->state[t] & ST_SENT_FLAGS) || svars->flags_done[t] < svars->flags_total[t])
		return 0;

	if ((svars->chan->ops[t] & OP_EXPUNGE) &&
	    (svars->ctx[t]->conf->trash || (svars->ctx[1-t]->conf->trash && svars->ctx[1-t]->conf->trash_remote_new))) {
		debug( "trashing in %s\n", str_ms[t] );
		for (tmsg = svars->ctx[t]->msgs; tmsg; tmsg = tmsg->next)
			if (tmsg->flags & F_DELETED) {
				if (svars->ctx[t]->conf->trash) {
					if (!svars->ctx[t]->conf->trash_only_new || !tmsg->srec || tmsg->srec->uid[1-t] < 0) {
						debug( "%s: trashing message %d\n", str_ms[t], tmsg->uid );
						svars->trash_total[t]++;
						stats( svars );
						sync_ref( svars );
						svars->drv[t]->trash_msg( svars->ctx[t], tmsg, msg_trashed, AUX );
						if (deref_check_cancel( svars ))
							return -1;
					} else
						debug( "%s: not trashing message %d - not new\n", str_ms[t], tmsg->uid );
				} else {
					if (!tmsg->srec || tmsg->srec->uid[1-t] < 0) {
						if (!svars->ctx[1-t]->conf->max_size || tmsg->size <= svars->ctx[1-t]->conf->max_size) {
							debug( "%s: remote trashing message %d\n", str_ms[t], tmsg->uid );
							svars->trash_total[t]++;
							stats( svars );
							cv = nfmalloc( sizeof(*cv) );
							cv->cb = msg_rtrashed;
							cv->aux = AUX;
							cv->srec = 0;
							cv->msg = tmsg;
							if (copy_msg( cv ))
								return -1;
						} else
							debug( "%s: not remote trashing message %d - too big\n", str_ms[t], tmsg->uid );
					} else
						debug( "%s: not remote trashing message %d - not new\n", str_ms[t], tmsg->uid );
				}
			}
	}
	svars->state[t] |= ST_SENT_TRASH;
	sync_close( svars, t );
	return 0;
}

static void
msg_trashed( int sts, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_MSG_BAD)
		sts = DRV_BOX_BAD;
	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	svars->trash_done[t]++;
	stats( svars );
	sync_close( svars, t );
}

static void
msg_rtrashed( int sts, int uid, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	(void)uid;
	switch (sts) {
	case SYNC_OK:
	case SYNC_NOGOOD: /* the message is gone or heavily busted */
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	free( vars );
	svars->trash_done[t]++;
	stats( svars );
	sync_close( svars, t );
}

static void box_closed( int sts, void *aux );
static void box_closed_p2( sync_vars_t *svars, int t );

static void
sync_close( sync_vars_t *svars, int t )
{
	if ((~svars->state[t] & (ST_SENT_FIND_NEW|ST_SENT_TRASH)) ||
	    svars->find_new_done[t] < svars->find_new_total[t] ||
	    svars->trash_done[t] < svars->trash_total[t])
		return;

	if ((svars->chan->ops[t] & OP_EXPUNGE) /*&& !(svars->state[t] & ST_TRASH_BAD)*/) {
		debug( "expunging %s\n", str_ms[t] );
		svars->drv[t]->close( svars->ctx[t], box_closed, AUX );
	} else {
		box_closed_p2( svars, t );
	}
}

static void
box_closed( int sts, void *aux )
{
	SVARS_CHECK_RET;
	svars->state[t] |= ST_DID_EXPUNGE;
	box_closed_p2( svars, t );
}

static void
box_closed_p2( sync_vars_t *svars, int t )
{
	sync_rec_t *srec;
	int minwuid;
	char fbuf[16]; /* enlarge when support for keywords is added */

	svars->state[t] |= ST_CLOSED;
	if (!(svars->state[1-t] & ST_CLOSED))
		return;

	if ((svars->state[M] | svars->state[S]) & ST_DID_EXPUNGE) {
		/* This cleanup is not strictly necessary, as the next full sync
		   would throw out the dead entries anyway. But ... */

		minwuid = INT_MAX;
		if (svars->smaxxuid) {
			debug( "preparing entry purge - max expired slave uid is %d\n", svars->smaxxuid );
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!((srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) &&
				      (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) || (srec->status & S_EXPIRED))) &&
				    svars->smaxxuid < srec->uid[S] && minwuid > srec->uid[M])
					minwuid = srec->uid[M];
			}
			debug( "  min non-orphaned master uid is %d\n", minwuid );
		}

		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->uid[S] <= 0 || ((srec->status & S_DEL(S)) && (svars->state[S] & ST_DID_EXPUNGE))) {
				if (srec->uid[M] <= 0 || ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE)) ||
				    ((srec->status & S_EXPIRED) && svars->maxuid[M] >= srec->uid[M] && minwuid > srec->uid[M])) {
					debug( "  -> killing (%d,%d)\n", srec->uid[M], srec->uid[S] );
					srec->status = S_DEAD;
					Fprintf( svars->jfp, "- %d %d\n", srec->uid[M], srec->uid[S] );
				} else if (srec->uid[S] > 0) {
					debug( "  -> orphaning (%d,[%d])\n", srec->uid[M], srec->uid[S] );
					Fprintf( svars->jfp, "> %d %d 0\n", srec->uid[M], srec->uid[S] );
					srec->uid[S] = 0;
				}
			} else if (srec->uid[M] > 0 && ((srec->status & S_DEL(M)) && (svars->state[M] & ST_DID_EXPUNGE))) {
				debug( "  -> orphaning ([%d],%d)\n", srec->uid[M], srec->uid[S] );
				Fprintf( svars->jfp, "< %d %d 0\n", srec->uid[M], srec->uid[S] );
				srec->uid[M] = 0;
			}
		}
	}

	Fprintf( svars->nfp, "%d:%d %d:%d:%d\n", svars->uidval[M], svars->maxuid[M], svars->uidval[S], svars->smaxxuid, svars->maxuid[S] );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		Fprintf( svars->nfp, "%d %d %s%s\n", srec->uid[M], srec->uid[S],
		         srec->status & S_EXPIRED ? "X" : "", fbuf );
	}

	Fclose( svars->nfp );
	Fclose( svars->jfp );
	if (!(DFlags & KEEPJOURNAL)) {
		/* order is important! */
		rename( svars->nname, svars->dname );
		unlink( svars->jname );
	}

	sync_bail( svars );
}

static void
sync_bail( sync_vars_t *svars )
{
	sync_rec_t *srec, *nsrec;

	for (srec = svars->srecs; srec; srec = nsrec) {
		nsrec = srec->next;
		free( srec );
	}
	unlink( svars->lname );
	sync_bail1( svars );
}

static void
sync_bail1( sync_vars_t *svars )
{
	close( svars->lfd );
	sync_bail2( svars );
}

static void
sync_bail2( sync_vars_t *svars )
{
	free( svars->lname );
	free( svars->nname );
	free( svars->jname );
	free( svars->dname );
	error( "" );
	sync_deref( svars );
}

static int sync_deref( sync_vars_t *svars )
{
	if (!--svars->ref_count) {
		void (*cb)( int sts, void *aux ) = svars->cb;
		void *aux = svars->aux;
		int ret = svars->ret;
		free( svars );
		cb( ret, aux );
		return -1;
	}
	return 0;
}
