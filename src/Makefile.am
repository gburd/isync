if with_compat
compat_dir = compat
endif
SUBDIRS = $(compat_dir)

bin_PROGRAMS = mbsync mdconvert

mbsync_SOURCES = main.c sync.c config.c util.c socket.c drv_imap.c drv_maildir.c
mbsync_LDADD = -ldb $(SSL_LIBS) $(SOCK_LIBS)
noinst_HEADERS = isync.h

mdconvert_SOURCES = mdconvert.c
mdconvert_LDADD = -ldb

man_MANS = mbsync.1 mdconvert.1
EXTRA_DIST = run-tests.pl mbsyncrc.sample $(man_MANS)
