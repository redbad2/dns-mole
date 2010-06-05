#ifndef DNSM_QUERY_H
#define DNSM_QUERY_H

#include "domain.h"

typedef enum {
	A = 0,
	MX,
	PTR,
	NS,
	CNAME
} RR_type;

struct Query {
	char q_domain_name[MAX_DN_LENGTH];
	time_t q_time;
	unsigned int q_ttl;
	RR_type q_type;
	char * q_value;
	unsigned int q_ip; 
};

struct Qlist_entry {
	struct Query ql_query;
	struct Qlist_entry * ql_next;
	struct Qlist_entry * ql_prev;
};

struct Qlist_entry * query_list;

void qlist_init();
int qlist_insert(struct Query * q);

#endif /* DNSM_QUERY_H */
