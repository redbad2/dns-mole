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

typedef struct answer {
	unsigned int ttl;
	RR_type type;
	u_char * value;
} answer;

typedef struct Query {
	char dname[MAX_LENGTH];
	time_t time;
	unsigned int srcip;
	unsigned int dstip;
	int ansnum;
	answer * answers;
	struct Query * prev;
	struct Query * next;
} query;

void query_empty(query * q);
void query_insert_before(query * q1, query * q2);
void query_insert_after(query * q1, query * q2);
void query_remove(query * q);

#endif /* DNSM_QUERY_H */
