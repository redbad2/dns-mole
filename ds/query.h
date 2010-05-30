#ifndef DNM_QUERY_H
#define DNM_QUERY_H

#include<ds/types.h>

#define MAX_DN_LENGTH 256

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
	uint32 q_ttl;
	RR_type q_type;
};

#endif /* DNM_QUERY_H */
