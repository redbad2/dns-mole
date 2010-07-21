/* dns_sniffer.c
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

#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>

#include "../include/dnsmole.h"
#include "../include/dns_sniffer.h"
#include "../include/error.h"
#include "../include/dns_parser.h"


int pcap_dloff(pcap_t *pd){
    int i;

    i = pcap_datalink(pd);
    switch (i){
	case DLT_EN10MB:
	    i = 14;
	    break;
        case DLT_IEEE802:
	    i = 22;
	    break;
	case DLT_FDDI:
	    i = 21;
	    break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
	    i = 4;
	    break;
	default:
	    i = -1;
	    break;
	}
	return i;
}

void _dns_sniffer(int fd, short event, void *arg) {
    struct moleWorld *myMole= (struct moleWorld *) arg;

    evtimer_add(&myMole->recv_ev, &myMole->tv);
    if(pcap_dispatch(myMole->p, 0, (void *) pcap_callback, (void *) myMole) < 0){
        fprintf(stderr,"[pcap_dispatch] error\n"); exit(EXIT_FAILURE);
    }
	
    return;
}

void pcap_callback(u_char *args,const struct pcap_pkthdr *pkthdr,
                        const u_char *packet){

        struct moleWorld *mWorld = (struct moleWorld *)args;
        static struct ip_hdr *ip_h;
        u_char *tmp;

    
        if(ph->caplen < mWorld->dl_lend + IP_LEN_MIN)
            return;
        
        tmp = packet + mWorld->dl_len;
        ip_h = (struct ip_hdr *) tmp;

        if(!(ip_h->ip_v == 4) || !(ip_h->ip_p == IP_PROTO_TCP) || !(ip_h->ip_p == IP_PROTO_UDP))
            return;
        
        if(ip_h->ip == IP_PROTO_TCP){


        query *q = (query *)malloc(sizeof(query));
        memset(q,0,sizeof(query);
        dns2query((u_char *)packet,pkthdr->len,q);
        q->qtime = pkthdr->ts.tv_sec;
        qlist_append(mWorld->query_list,q);
}
 
