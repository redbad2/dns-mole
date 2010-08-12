/* dnsmole.h
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

#ifndef DNM_DNSMOLE_H
#define DNM_DNSMOLE_H

#include <event.h>
#include <time.h>
#include <pcap.h>
#include <pcre.h>

#include "query.h"
#include "knowndomain.h"
#include "dns_sniffer.h"
#include "analyze.h"
#include "store_structures.h"
#include "statistics.h"
#include "error.h"

struct configuration{
    char *variable;
    void *where;
    int type;
    struct configuration *next;
};

struct parameter{

    int learn_interval;
    int analyze_interval;

    int activity_drop;
    float activity_similarity;

    float black_ip_treshold;
    float o_white;
    float o_black;

    int subnet;
};

struct moleWorld{

    struct parameter parameters;

    kdomain *root_list;

    query *qlist_head;
    query *qlist_rear;

    int type;
    int count;
    int ipSpace;
    
    int dl_len;

    pcre *re;
    pcap_t *p;
    int pcap_fd;
    
    char *interface;
	
    struct event recv_ev;
    struct event learn_ev;
    struct event analyze_ev;

    struct timeval tv;
    struct timeval learn_tv;
    struct timeval analyze_tv;

    FILE *log_fp;

};


typedef struct configuration configuration; 
typedef struct moleWorld moleWorld;

void handler(int);
void set_signal(int);

configuration *create_t_configuration(const char *, void *, int );
void register_config(configuration *, const char *, void *, int);

void open_log(void *, const char *);
void close_log(void *);
void report(FILE *, int, int, const char *);

#endif
