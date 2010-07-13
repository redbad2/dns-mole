#ifndef DNSM_QUERY_H
#define DNSM_QUERY_H

#include <time.h>
#include <sys/types.h>

#define MAX_LENGTH 256

#define RR_TYPE_A 1
#define RR_TYPE_NS 2
#define RR_TYPE_CNAME 5
#define RR_TYPE_PTR 12
#define RR_TYPE_MX 15

typedef enum {
	A = RR_TYPE_A,
	MX = RR_TYPE_MX,
	PTR = RR_TYPE_PTR,
	NS = RR_TYPE_NS,
	CNAME = RR_TYPE_CNAME
} RR_type;

struct Query {
	char q_dname[MAX_LENGTH];
	time_t q_time;
	unsigned int q_ttl;
	RR_type q_type;
	char * q_value;
	unsigned int q_srcip;
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
void qlist_reset();
int qlist_append(query * q);
int qlist_insert_before(qentry * qe, query * q);
int qlist_insert_after(qentry * qe, query * q);
void qlist_remove(qentry * q);

void check_free(void * p);

#endif /* DNSM_QUERY_H */
