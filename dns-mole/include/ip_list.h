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

#ifndef DNSM_IP_LIST_H
#define DNSM_IP_LIST_H

#include <time.h>
#include <sys/types.h>

struct ip_domains{

    char *d_name; 
    int count;
    struct ip_domains *next;
    struct ip_domains *prev;
    float level;
};

struct bad_ip_structure{

    unsigned int ip;
    struct ip_domains *q_domains;
    struct bad_ip_structure *prev;
    struct bad_ip_structure *next;
    int sum, num; 

};

typedef struct ip_domains domains;
typedef struct bad_ip_structure ip_list;

ip_list *ip_new(unsigned int, char *,int);
domains *new_domain(char *,int);
void ip_remove(ip_list *);
ip_list *search_ip(ip_list *, unsigned int);
void ip_add_domain(ip_list *,char *,int);
void ip_remove_domain(ip_list *,char *);

int return_count(ip_list *,char *);
void add_count(ip_list *,char *);

void clean_ip_2_domains(domains *);
void clean_ip_structure(ip_list *);

#endif
