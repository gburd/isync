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

#include "isync.h"

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>

typedef struct imap_server_conf {
	struct imap_server_conf *next;
	char *name;
	server_conf_t sconf;
	char *user;
	char *pass;
	int max_in_progress;
#ifdef HAVE_LIBSSL
	unsigned require_ssl:1;
	unsigned require_cram:1;
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

#define MAX_LIST_DEPTH 5

typedef struct parse_list_state {
	list_t *head, **stack[MAX_LIST_DEPTH];
	int level, need_bytes;
} parse_list_state_t;

struct imap_cmd;

typedef struct imap_store {
	store_t gen;
	const char *prefix;
	int ref_count;
	/* trash folder's existence is not confirmed yet */
	enum { TrashUnknown, TrashChecking, TrashKnown } trashnc;
	unsigned got_namespace:1;
	list_t *ns_personal, *ns_other, *ns_shared; /* NAMESPACE info */
	message_t **msgapp; /* FETCH results */
	unsigned caps; /* CAPABILITY results */
	parse_list_state_t parse_list_sts;
	/* command queue */
	int nexttag, num_in_progress;
	struct imap_cmd *pending, **pending_append;
	struct imap_cmd *in_progress, **in_progress_append;

	/* Used during sequential operations like connect */
	enum { GreetingPending = 0, GreetingBad, GreetingOk, GreetingPreauth } greeting;
	int canceling; /* imap_cancel() is in progress */
	union {
		void (*imap_open)( store_t *srv, void *aux );
		void (*imap_cancel)( void *aux );
	} callbacks;
	void *callback_aux;

	conn_t conn; /* this is BIG, so put it last */
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
			high_prio:1, /* if command is queued, put it at the front of the queue. */
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
#ifdef HAVE_LIBSSL
	CRAM,
	STARTTLS,
#endif
	UIDPLUS,
	LITERALPLUS,
	NAMESPACE
};

static const char *cap_list[] = {
	"LOGINDISABLED",
#ifdef HAVE_LIBSSL
	"AUTH=CRAM-MD5",
	"STARTTLS",
#endif
	"UIDPLUS",
	"LITERAL+",
	"NAMESPACE"
};

#define RESP_OK       0
#define RESP_NO       1
#define RESP_CANCEL   2

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

static void
done_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd, int response )
{
	cmd->param.done( ctx, cmd, response );
	free( cmd->param.data );
	free( cmd->cmd );
	free( cmd );
}

static int
send_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd )
{
	int bufl, litplus;
	const char *buffmt;
	char buf[1024];

	cmd->tag = ++ctx->nexttag;
	if (!cmd->param.data) {
		buffmt = "%d %s\r\n";
		litplus = 0;
	} else if ((cmd->param.to_trash && ctx->trashnc == TrashUnknown) || !CAP(LITERALPLUS)) {
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
	if (socket_write( &ctx->conn, buf, bufl, KeepOwn ) < 0)
		goto bail;
	if (litplus) {
		char *p = cmd->param.data;
		cmd->param.data = 0;
		if (socket_write( &ctx->conn, p, cmd->param.data_len, GiveOwn ) < 0 ||
		    socket_write( &ctx->conn, "\r\n", 2, KeepOwn ) < 0)
			goto bail;
	}
	if (cmd->param.to_trash && ctx->trashnc == TrashUnknown)
		ctx->trashnc = TrashChecking;
	cmd->next = 0;
	*ctx->in_progress_append = cmd;
	ctx->in_progress_append = &cmd->next;
	ctx->num_in_progress++;
	return 0;

  bail:
	done_imap_cmd( ctx, cmd, RESP_CANCEL );
	return -1;
}

static int
cmd_submittable( imap_store_t *ctx, struct imap_cmd *cmd )
{
	struct imap_cmd *cmdp;

	return !ctx->conn.write_buf &&
	       !(ctx->in_progress &&
	         (cmdp = (struct imap_cmd *)((char *)ctx->in_progress_append -
	                                     offsetof(struct imap_cmd, next)), 1) &&
	         (cmdp->param.cont || cmdp->param.data)) &&
	       !(cmd->param.to_trash && ctx->trashnc == TrashChecking) &&
	       ctx->num_in_progress < ((imap_store_conf_t *)ctx->gen.conf)->server->max_in_progress;
}

static int
flush_imap_cmds( imap_store_t *ctx )
{
	struct imap_cmd *cmd;

	while ((cmd = ctx->pending) && cmd_submittable( ctx, cmd )) {
		if (!(ctx->pending = cmd->next))
			ctx->pending_append = &ctx->pending;
		if (send_imap_cmd( ctx, cmd ) < 0)
			return -1;
	}
	return 0;
}

static void
cancel_pending_imap_cmds( imap_store_t *ctx )
{
	struct imap_cmd *cmd;

	while ((cmd = ctx->pending)) {
		if (!(ctx->pending = cmd->next))
			ctx->pending_append = &ctx->pending;
		done_imap_cmd( ctx, cmd, RESP_CANCEL );
	}
}

static void
cancel_submitted_imap_cmds( imap_store_t *ctx )
{
	struct imap_cmd *cmd;

	while ((cmd = ctx->in_progress)) {
		ctx->in_progress = cmd->next;
		/* don't update num_in_progress and in_progress_append - store is dead */
		done_imap_cmd( ctx, cmd, RESP_CANCEL );
	}
}

static int
submit_imap_cmd( imap_store_t *ctx, struct imap_cmd *cmd )
{
	assert( ctx );
	assert( ctx->gen.bad_callback );
	assert( cmd );
	assert( cmd->param.done );

	if ((ctx->pending && !cmd->param.high_prio) || !cmd_submittable( ctx, cmd )) {
		if (ctx->pending && cmd->param.high_prio) {
			cmd->next = ctx->pending;
			ctx->pending = cmd;
		} else {
			cmd->next = 0;
			*ctx->pending_append = cmd;
			ctx->pending_append = &cmd->next;
		}
		return 0;
	}

	return send_imap_cmd( ctx, cmd );
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
	nfvasprintf( &cmdp->cmd, fmt, ap );
	va_end( ap );
	return submit_imap_cmd( ctx, cmdp );
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
	if (!--sts->ref_count) {
		sts->callback( sts->ret_val, sts->callback_aux );
		free( sts );
	}
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

enum {
	LIST_OK,
	LIST_PARTIAL,
	LIST_BAD
};

static int
parse_imap_list( imap_store_t *ctx, char **sp, parse_list_state_t *sts )
{
	list_t *cur, **curp;
	char *s = *sp, *p;
	int bytes;

	assert( sts );
	assert( sts->level > 0 );
	curp = sts->stack[--sts->level];
	bytes = sts->need_bytes;
	if (bytes >= 0) {
		sts->need_bytes = -1;
		if (!bytes)
			goto getline;
		cur = (list_t *)((char *)curp - offsetof(list_t, next));
		s = cur->val + cur->len - bytes;
		goto getbytes;
	}

	for (;;) {
		while (isspace( (unsigned char)*s ))
			s++;
		if (sts->level && *s == ')') {
			s++;
			curp = sts->stack[--sts->level];
			goto next;
		}
		*curp = cur = nfmalloc( sizeof(*cur) );
		cur->val = 0; /* for clean bail */
		curp = &cur->next;
		*curp = 0; /* ditto */
		if (*s == '(') {
			/* sublist */
			if (sts->level == MAX_LIST_DEPTH)
				goto bail;
			s++;
			cur->val = LIST;
			sts->stack[sts->level++] = curp;
			curp = &cur->child;
			*curp = 0; /* for clean bail */
			goto next2;
		} else if (ctx && *s == '{') {
			/* literal */
			bytes = cur->len = strtol( s + 1, &s, 10 );
			if (*s != '}' || *++s)
				goto bail;

			s = cur->val = nfmalloc( cur->len );

		  getbytes:
			bytes -= socket_read( &ctx->conn, s, bytes );
			if (bytes > 0)
				goto postpone;

			if (DFlags & XVERBOSE) {
				puts( "=========" );
				fwrite( cur->val, cur->len, 1, stdout );
				puts( "=========" );
			}

		  getline:
			if (!(s = socket_read_line( &ctx->conn )))
				goto postpone;
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
				if (sts->level && *s == ')')
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

	  next:
		if (!sts->level)
			break;
	  next2:
		if (!*s)
			goto bail;
	}
	*sp = s;
	return LIST_OK;

  postpone:
	if (sts->level < MAX_LIST_DEPTH) {
		sts->stack[sts->level++] = curp;
		sts->need_bytes = bytes;
		return LIST_PARTIAL;
	}
  bail:
	free_list( sts->head );
	return LIST_BAD;
}

static void
parse_list_init( parse_list_state_t *sts )
{
	sts->need_bytes = -1;
	sts->level = 1;
	sts->head = 0;
	sts->stack[0] = &sts->head;
}

static list_t *
parse_list( char **sp )
{
	parse_list_state_t sts;
	parse_list_init( &sts );
	if (parse_imap_list( 0, sp, &sts ) == LIST_OK)
		return sts.head;
	return NULL;
}

static int
parse_fetch( imap_store_t *ctx, list_t *list )
{
	list_t *tmp, *flags;
	char *body = 0, *tuid = 0;
	imap_message_t *cur;
	msg_data_t *msgdata;
	struct imap_cmd *cmdp;
	int uid = 0, mask = 0, status = 0, size = 0;
	unsigned i;

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
			} else if (!strcmp( "BODY[HEADER.FIELDS", tmp->val )) {
				tmp = tmp->next;
				if (is_list( tmp )) {
					tmp = tmp->next;
					if (!is_atom( tmp ) || strcmp( tmp->val, "]" ))
						goto bfail;
					tmp = tmp->next;
					if (!is_atom( tmp ) || memcmp( tmp->val, "X-TUID: ", 8 ))
						goto bfail;
					tuid = tmp->val + 8;
				} else {
				  bfail:
					error( "IMAP error: unable to parse BODY[HEADER.FIELDS ...]\n" );
				}
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
		cur->gen.srec = 0;
		if (tuid)
			strncpy( cur->gen.tuid, tuid, TUIDL );
		else
			cur->gen.tuid[0] = 0;
		if (ctx->gen.uidnext <= uid) /* in case the server sends no UIDNEXT */
			ctx->gen.uidnext = uid + 1;
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
		if (!(arg = next_arg( &s )) || !(ctx->gen.uidnext = atoi( arg ))) {
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

static void
imap_socket_read( void *aux )
{
	imap_store_t *ctx = (imap_store_t *)aux;
	struct imap_cmd *cmdp, **pcmdp;
	char *cmd, *arg, *arg1, *p;
	int resp, resp2, tag, greeted;

	greeted = ctx->greeting;
	if (ctx->parse_list_sts.level) {
		cmd = 0;
		goto do_fetch;
	}
	for (;;) {
		if (!(cmd = socket_read_line( &ctx->conn )))
			return;

		arg = next_arg( &cmd );
		if (*arg == '*') {
			arg = next_arg( &cmd );
			if (!arg) {
				error( "IMAP error: malformed untagged response\n" );
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
			else if ((arg1 = next_arg( &cmd ))) {
				if (!strcmp( "EXISTS", arg1 ))
					ctx->gen.count = atoi( arg );
				else if (!strcmp( "RECENT", arg1 ))
					ctx->gen.recent = atoi( arg );
				else if(!strcmp ( "FETCH", arg1 )) {
					parse_list_init( &ctx->parse_list_sts );
				  do_fetch:
					if ((resp = parse_imap_list( ctx, &cmd, &ctx->parse_list_sts )) == LIST_BAD)
						break; /* stream is likely to be useless now */
					if (resp == LIST_PARTIAL)
						return;
					if (parse_fetch( ctx, ctx->parse_list_sts.head ) < 0)
						break; /* this may mean anything, so prefer not to spam the log */
				}
			} else {
				error( "IMAP error: unrecognized untagged response '%s'\n", arg );
				break; /* this may mean anything, so prefer not to spam the log */
			}
			if (greeted == GreetingPending) {
				imap_ref( ctx );
				imap_open_store_greeted( ctx );
				if (imap_deref( ctx ))
					return;
			}
			continue;
		} else if (!ctx->in_progress) {
			error( "IMAP error: unexpected reply: %s %s\n", arg, cmd ? cmd : "" );
			break; /* this may mean anything, so prefer not to spam the log */
		} else if (*arg == '+') {
			/* This can happen only with the last command underway, as
			   it enforces a round-trip. */
			cmdp = ctx->in_progress;
			if (cmdp->param.data) {
				if (cmdp->param.to_trash)
					ctx->trashnc = TrashKnown; /* Can't get NO [TRYCREATE] any more. */
				p = cmdp->param.data;
				cmdp->param.data = 0;
				if (socket_write( &ctx->conn, p, cmdp->param.data_len, GiveOwn ) < 0)
					return;
			} else if (cmdp->param.cont) {
				if (cmdp->param.cont( ctx, cmdp, cmd ))
					return;
			} else {
				error( "IMAP error: unexpected command continuation request\n" );
				break;
			}
			if (socket_write( &ctx->conn, "\r\n", 2, KeepOwn ) < 0)
				return;
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
			arg = next_arg( &cmd );
			if (!strcmp( "OK", arg )) {
				if (cmdp->param.to_trash)
					ctx->trashnc = TrashKnown; /* Can't get NO [TRYCREATE] any more. */
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
						cmd2->gen.param.high_prio = 1;
						p = strchr( cmdp->cmd, '"' );
						if (imap_exec( ctx, &cmd2->gen, get_cmd_result_p2,
						               "CREATE %.*s", strchr( p + 1, '"' ) - p + 1, p ) < 0)
							return;
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
			done_imap_cmd( ctx, cmdp, resp );
			if (imap_deref( ctx ))
				return;
			if (ctx->canceling && !ctx->in_progress) {
				ctx->canceling = 0;
				ctx->callbacks.imap_cancel( ctx->callback_aux );
				return;
			}
		}
		if (flush_imap_cmds( ctx ) < 0)
			return;
	}
	imap_invoke_bad_callback( ctx );
}

static void
get_cmd_result_p2( imap_store_t *ctx, struct imap_cmd *cmd, int response )
{
	struct imap_cmd_trycreate *cmdp = (struct imap_cmd_trycreate *)cmd;
	struct imap_cmd *ocmd = cmdp->orig_cmd;

	if (response != RESP_OK) {
		done_imap_cmd( ctx, ocmd, response );
	} else {
		ctx->gen.uidnext = 1;
		if (ocmd->param.to_trash)
			ctx->trashnc = TrashKnown;
		ocmd->param.create = 0;
		ocmd->param.high_prio = 1;
		submit_imap_cmd( ctx, ocmd );
	}
}

/******************* imap_cancel_store *******************/

static void
imap_cancel_store( store_t *gctx )
{
	imap_store_t *ctx = (imap_store_t *)gctx;

	socket_close( &ctx->conn );
	cancel_submitted_imap_cmds( ctx );
	cancel_pending_imap_cmds( ctx );
	free_generic_messages( ctx->gen.msgs );
	free_string_list( ctx->gen.boxes );
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
do_cram_auth( imap_store_t *ctx, struct imap_cmd *cmdp, const char *prompt )
{
	imap_server_conf_t *srvc = ((imap_store_conf_t *)ctx->gen.conf)->server;
	char *resp;
	int l;

	cmdp->param.cont = 0;

	cram( prompt, srvc->user, srvc->pass, &resp, &l );

	if (DFlags & VERBOSE)
		printf( ">+> %s\n", resp );
	return socket_write( &ctx->conn, resp, l, GiveOwn );
}
#endif

static void imap_open_store_connected( int, void * );
#ifdef HAVE_LIBSSL
static void imap_open_store_tlsstarted1( int, void * );
#endif
static void imap_open_store_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_authenticate( imap_store_t * );
#ifdef HAVE_LIBSSL
static void imap_open_store_authenticate_p2( imap_store_t *, struct imap_cmd *, int );
static void imap_open_store_tlsstarted2( int, void * );
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
	ctx->ref_count = 1;
	ctx->callbacks.imap_open = cb;
	ctx->callback_aux = aux;
	set_bad_callback( &ctx->gen, (void (*)(void *))imap_open_store_bail, ctx );
	ctx->in_progress_append = &ctx->in_progress;
	ctx->pending_append = &ctx->pending;

	socket_init( &ctx->conn, &srvc->sconf,
	             (void (*)( void * ))imap_invoke_bad_callback,
	             imap_socket_read, (int (*)(void *))flush_imap_cmds, ctx );
	socket_connect( &ctx->conn, imap_open_store_connected );
}

static void
imap_open_store_connected( int ok, void *aux )
{
	imap_store_t *ctx = (imap_store_t *)aux;
#ifdef HAVE_LIBSSL
	imap_store_conf_t *cfg = (imap_store_conf_t *)ctx->gen.conf;
	imap_server_conf_t *srvc = cfg->server;
#endif

	if (!ok)
		imap_open_store_bail( ctx );
#ifdef HAVE_LIBSSL
	else if (srvc->sconf.use_imaps)
		socket_start_tls( &ctx->conn, imap_open_store_tlsstarted1 );
#endif
}

#ifdef HAVE_LIBSSL
static void
imap_open_store_tlsstarted1( int ok, void *aux )
{
	imap_store_t *ctx = (imap_store_t *)aux;

	if (!ok)
		imap_open_store_ssl_bail( ctx );
}
#endif

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

		if (!srvc->sconf.use_imaps &&
		    (srvc->sconf.use_sslv2 || srvc->sconf.use_sslv3 || srvc->sconf.use_tlsv1)) {
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
	else
		socket_start_tls( &ctx->conn, imap_open_store_tlsstarted2 );
}

static void
imap_open_store_tlsstarted2( int ok, void *aux )
{
	imap_store_t *ctx = (imap_store_t *)aux;

	if (!ok)
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
	if (!ctx->conn.ssl)
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
	ctx->trashnc = TrashUnknown;
	ctx->callbacks.imap_open( &ctx->gen, ctx->callback_aux );
}

#ifdef HAVE_LIBSSL
static void
imap_open_store_ssl_bail( imap_store_t *ctx )
{
	/* This avoids that we try to send LOGOUT to an unusable socket. */
	socket_close( &ctx->conn );
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

	ctx->gen.uidnext = 0;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	cmd->gen.param.create = create;
	cmd->gen.param.trycreate = 1;
	imap_exec( ctx, &cmd->gen, imap_done_simple_box,
	           "SELECT \"%s%s\"", prefix, gctx->name );
}

/******************* imap_load *******************/

static int imap_submit_load( imap_store_t *, const char *, int, struct imap_cmd_refcounted_state * );
static void imap_load_p2( imap_store_t *, struct imap_cmd *, int );

static void
imap_load( store_t *gctx, int minuid, int maxuid, int newuid, int *excs, int nexcs,
           void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	int i, j, bl;
	char buf[1000];

	if (!ctx->gen.count) {
		free( excs );
		cb( DRV_OK, aux );
	} else {
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
			if (imap_submit_load( ctx, buf, 0, sts ) < 0)
				goto done;
		}
		if (maxuid == INT_MAX)
			maxuid = ctx->gen.uidnext ? ctx->gen.uidnext - 1 : 1000000000;
		if (maxuid >= minuid) {
			if ((ctx->gen.opts & OPEN_FIND) && minuid < newuid) {
				sprintf( buf, "%d:%d", minuid, newuid - 1 );
				if (imap_submit_load( ctx, buf, 0, sts ) < 0)
					goto done;
				sprintf( buf, "%d:%d", newuid, maxuid );
			} else {
				sprintf( buf, "%d:%d", minuid, maxuid );
			}
			imap_submit_load( ctx, buf, (ctx->gen.opts & OPEN_FIND), sts );
		}
	  done:
		free( excs );
		imap_refcounted_done( sts );
	}
}

static int
imap_submit_load( imap_store_t *ctx, const char *buf, int tuids, struct imap_cmd_refcounted_state *sts )
{
	return imap_exec( ctx, imap_refcounted_new_cmd( sts ), imap_load_p2,
	                  "UID FETCH %s (UID%s%s%s)", buf,
	                  (ctx->gen.opts & OPEN_FLAGS) ? " FLAGS" : "",
	                  (ctx->gen.opts & OPEN_SIZE) ? " RFC822.SIZE" : "",
	                  tuids ? " BODY.PEEK[HEADER.FIELDS (X-TUID)]" : "");
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

	buf[imap_make_flags( flags, buf )] = 0;
	return imap_exec( ctx, imap_refcounted_new_cmd( sts ), imap_set_flags_p2,
	                  "UID STORE %d %cFLAGS.SILENT %s", uid, what, buf );
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

/******************* imap_find_new_msgs *******************/

static void
imap_find_new_msgs( store_t *gctx,
                    void (*cb)( int sts, void *aux ), void *aux )
{
	imap_store_t *ctx = (imap_store_t *)gctx;
	struct imap_cmd_simple *cmd;

	INIT_IMAP_CMD(imap_cmd_simple, cmd, cb, aux)
	imap_exec( (imap_store_t *)ctx, &cmd->gen, imap_done_simple_box,
	           "UID FETCH %d:1000000000 (UID BODY.PEEK[HEADER.FIELDS (X-TUID)])", ctx->gen.uidnext );
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
	imap_store_t *ctx = (imap_store_t *)gctx;

	cancel_pending_imap_cmds( ctx );
	if (ctx->in_progress) {
		ctx->canceling = 1;
		ctx->callbacks.imap_cancel = cb;
		ctx->callback_aux = aux;
	} else {
		cb( aux );
	}
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
	server->sconf.use_tlsv1 = 1;
#endif
	server->max_in_progress = INT_MAX;

	while (getcline( cfg ) && cfg->cmd) {
		if (!strcasecmp( "Host", cfg->cmd )) {
			/* The imap[s]: syntax is just a backwards compat hack. */
#ifdef HAVE_LIBSSL
			if (!memcmp( "imaps:", cfg->val, 6 )) {
				cfg->val += 6;
				server->sconf.use_imaps = 1;
				server->sconf.use_sslv2 = 1;
				server->sconf.use_sslv3 = 1;
			} else
#endif
			{
				if (!memcmp( "imap:", cfg->val, 5 ))
					cfg->val += 5;
			}
			if (!memcmp( "//", cfg->val, 2 ))
				cfg->val += 2;
			server->sconf.host = nfstrdup( cfg->val );
		}
		else if (!strcasecmp( "User", cfg->cmd ))
			server->user = nfstrdup( cfg->val );
		else if (!strcasecmp( "Pass", cfg->cmd ))
			server->pass = nfstrdup( cfg->val );
		else if (!strcasecmp( "Port", cfg->cmd ))
			server->sconf.port = parse_int( cfg );
		else if (!strcasecmp( "PipelineDepth", cfg->cmd )) {
			if ((server->max_in_progress = parse_int( cfg )) < 1) {
				error( "%s:%d: PipelineDepth must be at least 1\n", cfg->file, cfg->line );
				*err = 1;
			}
		}
#ifdef HAVE_LIBSSL
		else if (!strcasecmp( "CertificateFile", cfg->cmd )) {
			server->sconf.cert_file = expand_strdup( cfg->val );
			if (access( server->sconf.cert_file, R_OK )) {
				sys_error( "%s:%d: CertificateFile '%s'",
				           cfg->file, cfg->line, server->sconf.cert_file );
				*err = 1;
			}
		} else if (!strcasecmp( "RequireSSL", cfg->cmd ))
			server->require_ssl = parse_bool( cfg );
		else if (!strcasecmp( "UseIMAPS", cfg->cmd ))
			server->sconf.use_imaps = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv2", cfg->cmd ))
			server->sconf.use_sslv2 = parse_bool( cfg );
		else if (!strcasecmp( "UseSSLv3", cfg->cmd ))
			server->sconf.use_sslv3 = parse_bool( cfg );
		else if (!strcasecmp( "UseTLSv1", cfg->cmd ))
			server->sconf.use_tlsv1 = parse_bool( cfg );
		else if (!strcasecmp( "RequireCRAM", cfg->cmd ))
			server->require_cram = parse_bool( cfg );
#endif
		else if (!strcasecmp( "Tunnel", cfg->cmd ))
			server->sconf.tunnel = nfstrdup( cfg->val );
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
		if (!server->sconf.tunnel && !server->sconf.host) {
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
	imap_find_new_msgs,
	imap_set_flags,
	imap_trash_msg,
	imap_close,
	imap_cancel,
	imap_commit,
};
