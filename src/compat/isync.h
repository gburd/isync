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
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>

#include <sys/types.h>
#include <stdarg.h>

#define as(ar) (sizeof(ar)/sizeof(ar[0]))

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define ATTR_UNUSED __attribute__((unused))
# define ATTR_NORETURN __attribute__((noreturn))
# define ATTR_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
#else
# define ATTR_UNUSED
# define ATTR_NORETURN
# define ATTR_PRINTFLIKE(fmt,var)
#endif

typedef struct config {
	struct config *next;

	const char *server_name;
	const char *old_server_name;
	int servers;
	int old_servers;
	char *host;
	int port;
	char *user;
	char *pass;
	char *tunnel;
	unsigned int require_cram:1;
	unsigned int require_ssl:1;
	unsigned int use_imaps:1;
	unsigned int use_sslv2:1;
	unsigned int use_sslv3:1;
	unsigned int use_tlsv1:1;
	char *cert_file;

	const char *store_name;
	int stores;
	char *copy_deleted_to;
	unsigned int use_namespace:1;

	const char *channel_name;
	int channels;
	const char *alias;
	const char *box;
	const char *path; /* path relative to .maildir, or absolute path */
	int max_size;
	unsigned int max_messages;
	unsigned int expunge:1;
	unsigned int delete:1;
} config_t;

extern int Quiet, Verbose, Debug;

extern const char *Home;
extern int HomeLen;

extern config_t global, *boxes;

extern const char *maildir, *xmaildir, *folder, *inbox;
extern int o2o, altmap, delete, expunge;

/* config.c */
void load_config( const char *, config_t *** );
void write_config( int );
char *expand_strdup( const char * );
config_t *find_box( const char * );

/* convert.c */
void convert( config_t * );

/* util.c */
char *next_arg( char ** );
void *nfmalloc( size_t sz );
void *nfrealloc( void *mem, size_t sz );
char *nfstrdup( const char *str );
int nfvasprintf( char **str, const char *fmt, va_list va );
int nfasprintf( char **str, const char *fmt, ... );
int nfsnprintf( char *buf, int blen, const char *fmt, ... );
void ATTR_NORETURN oob( void );
