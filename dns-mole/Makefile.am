AUTOMAKE_OPTIONS = foreign
SUBDIRS = src include doc man

# what flags you want to pass to the C compiler & linker
CFLAGS = -Wall -O3 -ffast-math -g
LDFLAGS = -lm

inc = include
src = src

bin_PROGRAMS = dnsmole
include_HEADERS = $(inc)/analyze.h $(inc)/dnsmole.h $(inc)/dns_parser.h $(inc)/dns_sniffer.h $(inc)/error.h $(inc)/knowndomain.h $(inc)/query.h $(inc)/statistics.h $(inc)/store_structures.h
dnsmole_SOURCES = $(src)/analyze.c $(src)/dnsmole.c $(src)/dns_parser.c $(src)/dns_sniffer.c $(src)/knowndomain.c $(src)/log.c $(src)/query.c $(src)/statistics.c $(src)/store_structures.c
