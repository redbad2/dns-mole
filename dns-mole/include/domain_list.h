/* domain_list.h
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

#ifndef DNSM_DOMAIN_LIST_H
#define DNSM_DOMAIN_LIST_H

#include "ip_list.h"

struct domains_to_ip{

    struct ip_list *ip;
    struct domain_ip *next;
    struct domain_ip *prev;
    int count;
};

struct q_domain_structure{

    char *name;
    struct domains_to_ip *ip;
    struct q_domain_structure *prev;
    struct q_domain_structure *next;
    float type;

};

typedef struct q_domain_structure query_domain;
typedef struct domains_to_ip d_2_ip;

query_domain *new_query_domain(char *);
void add_ip_2_domain(query_domain *,ip *);
query_domain *find_by_name(query_domain *,char *);
void free_ip_in_domain(d_2_ip *);
void remove_domain(query_domain *);

#endif
