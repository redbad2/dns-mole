#ifndef DNM_KNOWNDOMAIN_H
#define DNM_KNOWNDOMAIN_H

#include "types.h"

#include <pcre.h>

struct KnownDomain {
    char *name;
    struct KnownDomain *kd_child;
    struct KnownDomain *next;
    struct KnownDomain *prev;
    int32 suspicious;
};

typedef struct KnownDomain kdomain;

kdomain *add_domain(kdomain *, kdomain *,int32 );
kdomain *new_domain_structure(char *);
void load_url(char *,pcre *,kdomain *,int32);
void read_list(kdomain *,const char *,int32);;

#endif
