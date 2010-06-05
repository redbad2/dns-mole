#ifndef DNM_KNOWNDOMAIN_H
#define DNM_KNOWNDOMAIN_H

#include "types.h"

#include <pcre.h>

struct KnownDomain {
    char *name;
    struct KnownDomain *kd_child;
    struct KnownDomain *next;
    struct KnownDomain *prev;
    int suspicious;
};

typedef struct KnownDomain kdomain;

kdomain *add_domain(kdomain *, kdomain *);
kdomain *new_domain_structure(char *);
void load_url(char *,pcre *,kdomain *);
void read_blacklist(const char *);

#endif
