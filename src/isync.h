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

#define _GNU_SOURCE

#include <config.h>

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#define as(ar) (sizeof(ar)/sizeof(ar[0]))

#define __stringify(x) #x
#define stringify(x) __stringify(x)

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define ATTR_UNUSED __attribute__((unused))
# define ATTR_NORETURN __attribute__((noreturn))
# define ATTR_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
#else
# define ATTR_UNUSED
# define ATTR_NORETURN
# define ATTR_PRINTFLIKE(fmt,var)
#endif

#ifdef __GNUC__
# define INLINE __inline__
#else
# define INLINE
#endif

#define EXE "mbsync"

typedef struct {
	const char *file;
	FILE *fp;
	char *buf;
	int bufl;
	int line;
	char *cmd, *val, *rest;
} conffile_t;

#define OP_NEW             (1<<0)
#define OP_RENEW           (1<<1)
#define OP_DELETE          (1<<2)
#define OP_FLAGS           (1<<3)
#define  OP_MASK_TYPE      (OP_NEW|OP_RENEW|OP_DELETE|OP_FLAGS) /* asserted in the target ops */
#define OP_EXPUNGE         (1<<4)
#define OP_CREATE          (1<<5)
#define XOP_PUSH           (1<<6)
#define XOP_PULL           (1<<7)
#define  XOP_MASK_DIR      (XOP_PUSH|XOP_PULL)
#define XOP_HAVE_TYPE      (1<<8)
#define XOP_HAVE_EXPUNGE   (1<<9)
#define XOP_HAVE_CREATE    (1<<10)

typedef struct driver driver_t;

typedef struct store_conf {
	struct store_conf *next;
	char *name;
	driver_t *driver;
	const char *path; /* should this be here? its interpretation is driver-specific */
	const char *map_inbox;
	const char *trash;
	unsigned max_size; /* off_t is overkill */
	unsigned trash_remote_new:1, trash_only_new:1;
} store_conf_t;

typedef struct string_list {
	struct string_list *next;
	char string[1];
} string_list_t;

#define M 0 /* master */
#define S 1 /* slave */

typedef struct channel_conf {
	struct channel_conf *next;
	const char *name;
	store_conf_t *stores[2];
	const char *boxes[2];
	char *sync_state;
	string_list_t *patterns;
	int ops[2];
	unsigned max_messages; /* for slave only */
} channel_conf_t;

typedef struct group_conf {
	struct group_conf *next;
	const char *name;
	string_list_t *channels;
} group_conf_t;

/* For message->flags */
/* Keep the mailbox driver flag definitions in sync! */
/* The order is according to alphabetical maildir flag sort */
#define F_DRAFT	     (1<<0) /* Draft */
#define F_FLAGGED    (1<<1) /* Flagged */
#define F_ANSWERED   (1<<2) /* Replied */
#define F_SEEN       (1<<3) /* Seen */
#define F_DELETED    (1<<4) /* Trashed */
#define NUM_FLAGS 5

/* For message->status */
#define M_RECENT       (1<<0) /* unsyncable flag; maildir_* depend on this being 1<<0 */
#define M_DEAD         (1<<1) /* expunged */
#define M_FLAGS        (1<<2) /* flags fetched */

typedef struct message {
	struct message *next;
	struct sync_rec *srec;
	/* string_list_t *keywords; */
	size_t size; /* zero implies "not fetched" */
	int uid;
	unsigned char flags, status;
} message_t;

/* For opts, both in store and driver_t->select() */
#define OPEN_OLD        (1<<0)
#define OPEN_NEW        (1<<1)
#define OPEN_FLAGS      (1<<2)
#define OPEN_SIZE       (1<<3)
#define OPEN_EXPUNGE    (1<<5)
#define OPEN_SETFLAGS   (1<<6)
#define OPEN_APPEND     (1<<7)
#define OPEN_FIND       (1<<8)

typedef struct store {
	struct store *next;
	store_conf_t *conf; /* foreign */
	string_list_t *boxes; /* _list results - own */
	unsigned listed:1; /* was _list already run? */

	void (*bad_callback)( void *aux );
	void *bad_callback_aux;

	/* currently open mailbox */
	const char *name; /* foreign! maybe preset? */
	char *path; /* own */
	message_t *msgs; /* own */
	int uidvalidity;
	unsigned opts; /* maybe preset? */
	/* note that the following do _not_ reflect stats from msgs, but mailbox totals */
	int count; /* # of messages */
	int recent; /* # of recent messages - don't trust this beyond the initial read */
} store_t;

static INLINE void
set_bad_callback( store_t *ctx, void (*cb)( void *aux ), void *aux )
{
	ctx->bad_callback = cb;
	ctx->bad_callback_aux = aux;
}

typedef struct {
	char *data;
	int len;
	unsigned char flags;
} msg_data_t;

#define DRV_OK          0
#define DRV_MSG_BAD     1
#define DRV_BOX_BAD     2
#define DRV_CANCELED    3

/* All memory belongs to the driver's user. */

/*
   This flag says that the driver CAN store messages with CRLFs,
   not that it must. The lack of it OTOH implies that it CANNOT,
   and as CRLF is the canonical format, we convert.
*/
#define DRV_CRLF        1

#define TUIDL 12

struct driver {
	int flags;
	int (*parse_store)( conffile_t *cfg, store_conf_t **storep, int *err );
	void (*cleanup)( void );
	void (*open_store)( store_conf_t *conf,
	                    void (*cb)( store_t *ctx, void *aux ), void *aux );
	void (*disown_store)( store_t *ctx );
	store_t *(*own_store)( store_conf_t *conf );
	void (*cancel_store)( store_t *ctx );
	void (*list)( store_t *ctx,
	              void (*cb)( int sts, void *aux ), void *aux );
	void (*prepare_opts)( store_t *ctx, int opts );
	void (*select)( store_t *ctx, int create,
	               void (*cb)( int sts, void *aux ), void *aux );
	void (*load)( store_t *ctx, int minuid, int maxuid, int *excs, int nexcs,
	              void (*cb)( int sts, void *aux ), void *aux );
	void (*fetch_msg)( store_t *ctx, message_t *msg, msg_data_t *data,
	                   void (*cb)( int sts, void *aux ), void *aux );
	void (*store_msg)( store_t *ctx, msg_data_t *data, int to_trash,
	                   void (*cb)( int sts, int uid, void *aux ), void *aux );
	void (*find_msg)( store_t *ctx, const char *tuid,
	                  void (*cb)( int sts, int uid, void *aux ), void *aux );
	void (*set_flags)( store_t *ctx, message_t *msg, int uid, int add, int del, /* msg can be null, therefore uid as a fallback */
	                   void (*cb)( int sts, void *aux ), void *aux );
	void (*trash_msg)( store_t *ctx, message_t *msg, /* This may expunge the original message immediately, but it needn't to */
	                   void (*cb)( int sts, void *aux ), void *aux );
	void (*close)( store_t *ctx, /* IMAP-style: expunge inclusive */
	               void (*cb)( int sts, void *aux ), void *aux );
	void (*cancel)( store_t *ctx, /* only not yet sent commands */
	                void (*cb)( void *aux ), void *aux );
	void (*commit)( store_t *ctx );
};


/* main.c */

extern int Pid;
extern char Hostname[256];
extern const char *Home;


/* util.c */

#define DEBUG        1
#define VERBOSE      2
#define XVERBOSE     4
#define QUIET        8
#define VERYQUIET    16
#define KEEPJOURNAL  32

extern int DFlags, Ontty;

void debug( const char *, ... );
void debugn( const char *, ... );
void info( const char *, ... );
void infon( const char *, ... );
void warn( const char *, ... );
void error( const char *, ... );

char *next_arg( char ** );

void add_string_list( string_list_t **list, const char *str );
void free_string_list( string_list_t *list );

void free_generic_messages( message_t * );

void *nfmalloc( size_t sz );
void *nfcalloc( size_t sz );
void *nfrealloc( void *mem, size_t sz );
char *nfstrdup( const char *str );
int nfvasprintf( char **str, const char *fmt, va_list va );
int nfasprintf( char **str, const char *fmt, ... );
int nfsnprintf( char *buf, int blen, const char *fmt, ... );
void ATTR_NORETURN oob( void );

char *expand_strdup( const char *s );

void sort_ints( int *arr, int len );

void arc4_init( void );
unsigned char arc4_getbyte( void );

/* sync.c */

extern const char *str_ms[2], *str_hl[2];

#define SYNC_OK       0 /* assumed to be 0 */
#define SYNC_FAIL     1
#define SYNC_BAD(ms)  (2<<(ms))
#define SYNC_NOGOOD   8 /* internal */
#define SYNC_CANCELED 16 /* internal */

/* All passed pointers must stay alive until cb is called. */
void sync_boxes( store_t *ctx[], const char *names[], channel_conf_t *chan,
                 void (*cb)( int sts, void *aux ), void *aux );

/* config.c */

#define N_DRIVERS 2
extern driver_t *drivers[N_DRIVERS];

extern channel_conf_t *channels;
extern group_conf_t *groups;
extern int global_ops[2];
extern char *global_sync_state;

int parse_bool( conffile_t *cfile );
int parse_int( conffile_t *cfile );
int parse_size( conffile_t *cfile );
int getcline( conffile_t *cfile );
int merge_ops( int cops, int ops[] );
int load_config( const char *filename, int pseudo );
void parse_generic_store( store_conf_t *store, conffile_t *cfg, int *err );

/* drv_*.c */
extern driver_t maildir_driver, imap_driver;
