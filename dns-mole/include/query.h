/* query.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * $Id$
 */

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

typedef struct Qlist qlist;
//struct Qlist qlist;

void qlist_init(qlist * ql);
void qlist_reset(qlist * ql);
int qlist_append(qlist * ql, query * q);
int qlist_insert_before(qlist * ql, qentry * qe, query * q);
int qlist_insert_after(qlist * ql, qentry * qe, query * q);
void qlist_remove(qlist * ql, qentry * q);


#endif /* DNSM_QUERY_H */
