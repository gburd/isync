bin_PROGRAMS = isync

isync_SOURCES = main.c config.c convert.c util.c
isync_LDADD = -ldb
noinst_HEADERS = isync.h

man_MANS = isync.1

exampledir = $(docdir)/examples
example_DATA = isyncrc.sample

EXTRA_DIST = $(example_DATA) $(man_MANS)
