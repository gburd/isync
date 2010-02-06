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

#include "isync.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

#if HAVE_GETOPT_LONG
# define _GNU_SOURCE
# include <getopt.h>
struct option Opts[] = {
	{"write", 0, NULL, 'w' },
	{"writeto", 0, NULL, 'W' },
	{"all", 0, NULL, 'a' },
	{"list", 0, NULL, 'l'},
	{"config", 1, NULL, 'c'},
	{"create", 0, NULL, 'C'},
	{"create-local", 0, NULL, 'L'},
	{"create-remote", 0, NULL, 'R'},
	{"delete", 0, NULL, 'd'},
	{"expunge", 0, NULL, 'e'},
	{"fast", 0, NULL, 'f'},
	{"help", 0, NULL, 'h'},
	{"remote", 1, NULL, 'r'},
	{"folder", 1, NULL, 'F'},
	{"maildir", 1, NULL, 'M'},
	{"one-to-one", 0, NULL, '1'},
	{"inbox", 1, NULL, 'I'},
	{"host", 1, NULL, 's'},
	{"port", 1, NULL, 'p'},
	{"debug", 0, NULL, 'D'},
	{"quiet", 0, NULL, 'q'},
	{"user", 1, NULL, 'u'},
	{"version", 0, NULL, 'v'},
	{"verbose", 0, NULL, 'V'},
	{0, 0, 0, 0}
};
#endif

static void
version( void )
{
	puts( PACKAGE " " VERSION );
	exit( 0 );
}

static void
usage( int code )
{
	fputs(
PACKAGE " " VERSION " - mbsync wrapper: IMAP4 to maildir synchronizer\n"
"Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>\n"
"Copyright (C) 2002-2004 Oswald Buddenhagen <ossi@users.sf.net>\n"
"usage:\n"
" " PACKAGE " [ flags ] mailbox [mailbox ...]\n"
" " PACKAGE " [ flags ] -a\n"
" " PACKAGE " [ flags ] -l\n"
"  -a, --all		synchronize all defined mailboxes\n"
"  -l, --list		list all defined mailboxes and exit\n"
"  -L, --create-local	create local maildir mailbox if nonexistent\n"
"  -R, --create-remote	create remote imap mailbox if nonexistent\n"
"  -C, --create		create both local and remote mailboxes if nonexistent\n"
"  -d, --delete		delete local msgs that don't exist on the server\n"
"  -e, --expunge		expunge	deleted messages\n"
"  -f, --fast		only fetch new messages\n"
"  -r, --remote BOX	remote mailbox\n"
"  -F, --folder DIR	remote IMAP folder containing mailboxes\n"
"  -M, --maildir DIR	local directory containing mailboxes\n"
"  -1, --one-to-one	map every IMAP <folder>/box to <maildir>/box\n"
"  -I, --inbox BOX	map IMAP INBOX to <maildir>/BOX (exception to -1)\n"
"  -s, --host HOST	IMAP server address\n"
"  -p, --port PORT	server IMAP port\n"
"  -u, --user USER	IMAP user name\n"
"  -c, --config CONFIG	read an alternate config file (default: ~/.isyncrc)\n"
"  -D, --debug		print debugging messages\n"
"  -V, --verbose		verbose mode (display network traffic)\n"
"  -q, --quiet		don't display progress info\n"
"  -v, --version		display version\n"
"  -h, --help		display this help message\n\n"
"Note that this is a wrapper binary only; the \"real\" isync is named \"mbsync\".\n"
"Options to permanently transform your old isync configuration:\n"
"  -w, --write		write permanent mbsync configuration\n"
"  -W, --writeto FILE	write permanent mbsync configuration to FILE\n",
	    code ? stderr : stdout );
	exit( code );
}

static const char *
strrstr( const char *h, const char *n )
{
	char *p = strstr( h, n );
	if (!p)
		return 0;
	do {
		h = p;
		p = strstr( h + 1, n );
	} while (p);
	return h;		
}

static void
add_arg( char ***args, const char *arg )
{
	int nu = 0;
	if (*args)
		for (; (*args)[nu]; nu++);
	*args = nfrealloc( *args, sizeof(char *) * (nu + 2));
	(*args)[nu] = nfstrdup( arg );
	(*args)[nu + 1] = 0;
}

#define OP_FAST            (1<<2)
#define OP_CREATE_REMOTE   (1<<3)
#define OP_CREATE_LOCAL    (1<<4)

int Quiet, Verbose, Debug;
config_t global, *boxes;
const char *maildir, *xmaildir, *folder, *inbox;
int o2o, altmap, delete, expunge;

const char *Home;
int HomeLen;

int
main( int argc, char **argv )
{
	config_t *box, **stor;
	char *config = 0, *outconfig = 0, **args;
	int i, pl, fd, mod, all, list, ops, writeout;
	struct stat st;
	char path1[_POSIX_PATH_MAX], path2[_POSIX_PATH_MAX];

	if (!(Home = getenv("HOME"))) {
		fputs( "Fatal: $HOME not set\n", stderr );
		return 1;
	}
	HomeLen = strlen( Home );

	/* defaults */
	/* XXX the precedence is borked:
	   it's defaults < cmdline < file instead of defaults < file < cmdline */
#ifdef BSD
	global.user = getenv( "USER" );
#else
	global.user = getenv( "LOGNAME" );
#endif
	global.port = 143;
	global.box = "INBOX";
	global.use_namespace = 1;
	global.require_ssl = 1;
	global.use_tlsv1 = 1;
	folder = "";
	maildir = "~";
	xmaildir = Home;

#define FLAGS "wW:alCLRc:defhp:qu:r:F:M:1I:s:vVD"

	mod = all = list = ops = writeout = Quiet = Verbose = Debug = 0;
#if HAVE_GETOPT_LONG
	while ((i = getopt_long( argc, argv, FLAGS, Opts, NULL )) != -1)
#else
	while ((i = getopt( argc, argv, FLAGS )) != -1)
#endif
	{
		switch (i) {
		case 'W':
			outconfig = optarg;
			/* plopp */
		case 'w':
			writeout = 1;
			break;
		case 'l':
			list = 1;
			/* plopp */
		case 'a':
			all = 1;
			break;
		case '1':
			o2o = 1;
			mod = 1;
			break;
		case 'C':
			ops |= OP_CREATE_REMOTE|OP_CREATE_LOCAL;
			break;
		case 'L':
			ops |= OP_CREATE_LOCAL;
			break;
		case 'R':
			ops |= OP_CREATE_REMOTE;
			break;
		case 'c':
			config = optarg;
			break;
		case 'd':
			delete = 1;
			break;
		case 'e':
			expunge = 1;
			break;
		case 'f':
			ops |= OP_FAST;
			break;
		case 'p':
			global.port = atoi( optarg );
			mod = 1;
			break;
		case 'r':
			global.box = optarg;
			mod = 1;
			break;
		case 'F':
			folder = optarg;
			mod = 1;
			break;
		case 'M':
			maildir = optarg;
			mod = 1;
			break;
		case 'I':
			inbox = optarg;
			mod = 1;
			break;
		case 's':
#if HAVE_LIBSSL
			if (!strncasecmp( "imaps:", optarg, 6 )) {
				global.use_imaps = 1;
				global.port = 993;
				global.use_sslv2 = 1;
				global.use_sslv3 = 1;
				optarg += 6;
			}
#endif
			global.host = optarg;
			mod = 1;
			break;
		case 'u':
			global.user = optarg;
			mod = 1;
			break;
		case 'D':
			Debug = 1;
			break;
		case 'V':
			Verbose++;
			break;
		case 'q':
			Quiet++;
			break;
		case 'v':
			version();
		case 'h':
			usage( 0 );
		default:
			usage( 1 );
		}
	}

	if (config) {
		if (*config != '/') {
			if (!getcwd( path1, sizeof(path1) )) {
				fprintf( stderr, "Can't obtain working directory\n" );
				return 1;
			}
			pl = strlen( path1 );
			nfsnprintf( path1 + pl, sizeof(path1) - pl, "/%s", config );
			config = path1;
		}
	} else {
		nfsnprintf( path1, sizeof(path1), "%s/.isyncrc", Home );
		config = path1;
	}
	stor = &boxes;
	load_config( config, &stor );

	if (!all && !o2o)
		for (i = optind; argv[i]; i++)
			if (!(box = find_box( argv[i] ))) {
				box = nfmalloc( sizeof(config_t) );
				memcpy( box, &global, sizeof(config_t) );
				box->path = argv[i];
				*stor = box;
				stor = &box->next;
				mod = 1;
			}

	if (writeout) {
		all = 1;
		if (mod)
			fprintf( stderr,
			         "Warning: command line switches that influence the resulting config file\n"
			         "have been supplied.\n" );
	} else {
		if (!argv[optind] && !all) {
			fprintf( stderr, "No mailbox specified. Try isync -h\n" );
			return 1;
		}
	}

	if (all) {
		if (o2o) {
			DIR * dir;
			struct dirent *de;

			if (!(dir = opendir( xmaildir ))) {
				fprintf( stderr, "%s: %s\n", xmaildir, strerror(errno) );
				return 1;
			}
			while ((de = readdir( dir ))) {
				if (*de->d_name == '.')
					continue;
				nfsnprintf( path2, sizeof(path2), "%s/%s/cur", xmaildir, de->d_name );
				if (stat( path2, &st ) || !S_ISDIR( st.st_mode ))
					continue;
				global.path = de->d_name;
				global.box = (inbox && !strcmp( inbox, global.path )) ?
					"INBOX" : global.path;
				convert( &global );
			}
			closedir( dir );
		} else
			for (box = boxes; box; box = box->next)
				convert( box );
	} else {
		for (i = optind; argv[i]; i++)
			if (o2o) {
				global.path = argv[i];
				global.box =
					(inbox && !strcmp( global.path, inbox )) ?
					"INBOX" : global.path;
				convert( &global );
			} else
				convert( find_box( argv[i] ) );
	}

	if (writeout) {
		if (!outconfig) {
			const char *p = strrchr( config, '/' );
			if (!p)
				p = config;
			p = strrstr( p, "isync" );
			if (!p)
				nfsnprintf( path2, sizeof(path2), "%s.mbsync", config );
			else
				nfsnprintf( path2, sizeof(path2), "%.*smb%s", p - config, config, p + 1 );
			outconfig = path2;
		}
		if ((fd = creat( outconfig, 0666 )) < 0) {
			fprintf( stderr, "Error: cannot write new config %s: %s\n", outconfig, strerror(errno) );
			return 1;
		}
	} else {
		strcpy( path2, "/tmp/mbsyncrcXXXXXX" );
		if ((fd = mkstemp( path2 )) < 0) {
			fprintf( stderr, "Can't create temp file\n" );
			return 1;
		}
	}
	write_config( fd );

	if (writeout)
		return 0;
	args = 0;
	add_arg( &args, "mbsync" );
	while (--Verbose >= 0)
		add_arg( &args, "-V" );
	if (Debug)
		add_arg( &args, "-D" );
	for (; Quiet; Quiet--)
		add_arg( &args, "-q" );
	add_arg( &args, "-cT" );
	add_arg( &args, path2 );
	if (ops & OP_FAST)
		add_arg( &args, "-Ln" );
	if (ops & OP_CREATE_REMOTE)
		add_arg( &args, "-Cm" );
	if (ops & OP_CREATE_LOCAL)
		add_arg( &args, "-Cs" );
	if (list)
		add_arg( &args, "-lC" );
	if (o2o) {
		if (all)
			add_arg( &args, "o2o" );
		else {
			char buf[1024];
			strcpy( buf, "o2o:" );
			strcat( buf, argv[optind] );
			while (argv[++optind]) {
				strcat( buf, "," );
				strcat( buf, argv[optind] );
			}
			add_arg( &args, buf );
		}
	} else {
		if (all)
			add_arg( &args, "-a" );
		else
			for (; argv[optind]; optind++)
				add_arg( &args, find_box( argv[optind] )->channel_name );
	}
	execvp( args[0], args );
	perror( args[0] );
	return 1;
}
