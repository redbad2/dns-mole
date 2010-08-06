/* bl_detection_structure.h
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

#ifndef DNSM_BL_DETECTION_STRUCTURE_H
#define DNSM_BL_DETECTION_STRUCTURE_H

struct bl_ip {

    unsigned int ip;
    int black_hosts; 
    int all_hosts;
    int white_hosts;
	struct bl_ip *prev;
	struct bl_ip *next;
};

struct bl_domain_ip {

    struct bl_ip *ip;
    struct bl_domain_ip *prev;
    struct bl_domain_ip *next;
    int count;
    
};

struct bl_domain {

    char *d_name;
    struct bl_domain_ip *domain_ip;
    struct bl_domain *prev;
    struct bl_domain *next;
    int queried_overall;
    float type;

};

typedef struct bl_ip bl_ip;
typedef struct bl_domain_ip bl_domain_ip;
typedef struct bl_domain bl_domain;

/* functions for blacklist domain structure */

bl_domain *new_bl_domain(const char *,float);
void add_ip_to_domain(bl_domain *,bl_ip *);
bl_domain *find_domain(bl_domain *,const char *);

void remove_ip_in_domain(bl_domain_ip *);
void remove_domain(bl_domain *,int);
bl_domain_ip *find_ip_in_domain(bl_domain_ip *,unsigned int);
			

/* functions for blacklist ip structure */

bl_ip *new_bl_ip(unsigned int);
bl_ip *find_ip(bl_ip *,unsigned int);
void remove_ip(bl_ip *);

#endif
