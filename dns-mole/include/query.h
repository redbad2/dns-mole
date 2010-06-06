#ifndef DNSM_QUERY_H
#define DNSM_QUERY_H

#include "knowndomain.h"
#include "types.h"

typedef enum {
	A = 1,
	MX = 15,
	PTR = 12,
	NS = 2,
	CNAME = 5
} RR_type;

struct Query {
	char q_dname[MAX_LENGTH];
	time_t q_time;
	uint32 q_ttl;
	RR_type q_type;
	char * q_value;
	uint32 q_srcip;
};

typedef struct Query query;

struct Qlist_entry {
	struct Query * qe_qry;
	struct Qlist_entry * qe_next;
	struct Qlist_entry * qe_prev;
};

typedef struct Qlist_entry qentry;

struct Qlist {
	qentry * head;
	qentry * rear;
};

struct Qlist qlist;

void qlist_init();
qentry * qlist_next(qentry * q);
int qlist_insert(query * q);
void qlist_delete(qentry * q);

#endif /* DNSM_QUERY_H */
