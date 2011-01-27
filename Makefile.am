AUTOMAKE_OPTIONS = foreign
SUBDIRS = src include doc man src/methods

# what flags you want to pass to the C compiler & linker
CFLAGS = -Wall -O3 -ffast-math -g -lsqlite3
LDFLAGS = -lm

inc = include
src = src
methods = src/methods

bin_PROGRAMS = dnsmole
include_HEADERS = $(inc)/dnsmole.h $(inc)/dns_parser.h $(inc)/dns_sniffer.h $(inc)/error.h $(inc)/knowndomain.h $(inc)/query.h $(inc)/config.h $(methods)/detection.h $(methods)/fhs-structures.h $(methods)/qss.h	
dnsmole_SOURCES = $(src)/dnsmole.c $(src)/dns_parser.c $(src)/dns_sniffer.c $(src)/knowndomain.c $(src)/log.c $(src)/query.c $(src)/config.c $(methods)/cor-detection.c $(methods)/ga-detection.c $(methods)/fhs-detection.c $(methods)/fhs-structures.c $(methods)/qss.c
