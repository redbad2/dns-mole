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

#define MAX_LENGTH 64

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

typedef struct responseSection{
	RR_type type;
	unsigned int ttl;
	
	unsigned char name[MAX_LENGTH];
	unsigned char value[MAX_LENGTH];
	unsigned int ip;
	
} responseSection;

typedef struct Query {
	time_t time;
	int suspicious; 
	int is_answer;
    int is_nxdomain;

	unsigned int srcip;
	unsigned int dstip;
	
	char dname[MAX_LENGTH];
	unsigned short q_type;
	
	unsigned int qnum;
	unsigned int ansnum;
	unsigned int nsnum;
	unsigned int addnum;
	
	responseSection *answers;
	responseSection *authority;
	responseSection *additional;
	
	struct Query * prev;
	struct Query * next;
		
} query;

void query_insert(query *, query *);
void query_remove(query *);

#endif /* DNSM_QUERY_H */
