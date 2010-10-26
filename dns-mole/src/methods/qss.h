/* qss.h
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

#ifndef DNSM_QSS_H
#define DNSM_QSS_H

#include "detection.h"

struct qss_ip{

    unsigned int ip;
    int black_hosts; 
    int all_hosts;
    int white_hosts;
    struct qss_ip *prev;
    struct qss_ip *next;
};

struct qss_ip_domain{

    struct qss_domain *ip;
    struct qss_ip_domain *prev;
    struct qss_ip_domain *next;

};

struct qss_domain_ip {

    struct qss_ip *ip;
    struct qss_domain_ip *prev;
    struct qss_domain_ip *next;
    int count;
    
};

struct qss_domain {

    char *d_name;
    struct qss_domain_ip *domain_ip;
    struct qss_domain *prev;
    struct qss_domain *next;
    int queried_overall;
    int queried_with_different_ip;
    float type;

};

typedef struct qss_ip qss_ip;
typedef struct qss_domain_ip qss_domain_ip;
typedef struct qss_domain qss_domain;
typedef struct qss_ip_domain qss_ip_domain;

/* functions: query sort domain structure */

qss_domain *new_domain(const char *, float);
void add_ip_to_domain(qss_domain *, qss_ip *);
qss_domain *find_domain(qss_domain *, const char *);

void remove_ip_in_domain(qss_domain_ip *);
void remove_domain(qss_domain *, qss_domain *);
void remove_domain_list(qss_domain *);
qss_domain_ip *find_ip_in_domain(qss_domain_ip *, unsigned int);
			

/* functions: query sort ip structure */

qss_ip *new_ip(unsigned int);
qss_ip *find_ip(qss_ip *, unsigned int);
void remove_ip(qss_ip **, int);
void remove_ip_single(qss_ip *);

#endif
