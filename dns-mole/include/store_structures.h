/* store_structure.h
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

#ifndef DNSM_STORE_STRUCTURE_H
#define DNSM_STORE_STRUCTURE_H

struct ip_store {

    unsigned int ip;
    int black_hosts; 
    int all_hosts;
    int white_hosts;
    struct ip_store *prev;
    struct ip_store *next;
};

struct domain_ip_store {

    struct ip_store *ip;
    struct domain_ip_store *prev;
    struct domain_ip_store *next;
    int count;
    
};

struct domain_store {

    char *d_name;
    struct domain_ip_store *domain_ip;
    struct domain_store *prev;
    struct domain_store *next;
    int queried_overall;
    int queried_with_different_ip;
    float type;

};

typedef struct ip_store ip_store;
typedef struct domain_ip_store domain_ip_store;
typedef struct domain_store domain_store;

/* functions for blacklist domain structure */

domain_store *new_domain(const char *, float);
void add_ip_to_domain(domain_store *, ip_store *);
domain_store *find_domain(domain_store *, const char *);

void remove_ip_in_domain(domain_ip_store *);
void remove_domain(domain_store *, int);
domain_ip_store *find_ip_in_domain(domain_ip_store *, unsigned int);
			

/* functions for blacklist ip structure */

ip_store *new_ip(unsigned int);
ip_store *find_ip(ip_store *, unsigned int);
void remove_ip(ip_store *);

#endif
