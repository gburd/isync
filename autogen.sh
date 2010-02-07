#! /bin/sh
set -e -v
make -f Makefile.am log
aclocal
autoheader
automake --add-missing
autoconf
