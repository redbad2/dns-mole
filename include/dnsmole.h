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

#include <stdio.h>

#include <event.h>
#include <time.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sqlite3.h>

#include "query.h"
#include "knowndomain.h"
#include "dns_sniffer.h"
#include "error.h"
#include "config.h"

struct parameter{

    int naive_analyze_interval;
    
    int activity_drop;
    int a_analyze_interval;
    float activity_bl_similarity;
    float activity_wl_similarity;

    int o_analyze_interval;
    float black_ip_treshold;
    float o_white;
    float o_black;

    int subnet;

    float s_threshold_total;
    float s_threshold_ptr;
    float s_threshold_mx;
    float s_threshold_balance;
    float s_threshold_ptr_rate;
    float s_threshold_mx_rate;
    int s_classify_interval;
    int s_analyze_interval;

};

struct functions{

    int (*filter) (void *);
    void (*analyze) (unsigned int,void *);
    void *function_data;    
};

struct moleWorld{

    struct parameter parameters;
    struct functions moleFunctions;

    kdomain *root_list;

    query *qlist_head;
    query *qlist_rear;

    int type;
    int count;
    int ipSpace;
    
    int dl_len;

    pcap_t *p;
    int pcap_fd;
    
    char *interface;
	
    struct event recv_ev;
    struct event analyze_ev;

    struct timeval tv;
    struct timeval analyze_tv;
	
    char *log_file;
    sqlite3 *db;
};


typedef struct moleWorld moleWorld;

void _analyzer(int , short , void *);

void handler(int);
void set_signal(int);

void openDB(void *, const char *);
void closeDB(void *);
void useDB(void *,const char *,...);

#endif
