#!/bin/sh
# $Id$
# Re-run the autotools programs in the correct order to generate a working build
libtoolize --copy
aclocal
autoheader
automake --add-missing --copy
autoconf
