/* dns_sniffer.h
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
 
#ifndef DNSM_PKTCAPTURE_H
#define DNSM_PKTCAPTURE_H

#include <pcap.h>
#include <net/ethernet.h>

#include "query.h"
#include "dnsmole.h"
#include "knowndomain.h"

#define DNS_QUERY_FILTER "tcp src port 53 or udp src port 53"
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

struct ip_header {
	unsigned char ip_ihl:4;
	unsigned char ip_version:4;
	unsigned char ip_tos;
	unsigned short ip_length;
	unsigned short ip_id;
	unsigned short ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	unsigned char ip_ttl;
	unsigned char ip_proto;
	unsigned short ip_checksum;
	unsigned int ip_src;
	unsigned int ip_dst;
};

struct udp_header {
	unsigned short uh_srcport;
	unsigned short uh_dstport;
	unsigned short uh_length;
	unsigned short uh_checksum;
};

struct tcp_header {
	unsigned short th_srcport;
	unsigned short th_dstport;
	unsigned int th_seq;
	unsigned int th_ack;
	unsigned short th_code;
#define TH_LEN(th) (((th)->th_code & 0xf000) >> 12)
	unsigned short th_win;
	unsigned short th_checksum;
	unsigned short th_urgpt;
};

struct dns_query_header {
	unsigned short dq_id;
	unsigned short dq_flags;
#define DQH_QR(dq) (((dq)->dq_flags & 0x8000) >> 15)
	unsigned short dq_qc;
	unsigned short dq_ac;
	unsigned short dq_nc;
	unsigned short dq_arc;
};


/*
 * count = -1 for infinite loop
 * count = 0 for stop until error
 */

int sniffer_setup(void *);
void _dns_sniffer(int , short , void *);

void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* handle ethernet packet */
unsigned short get_ethernet_type (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

void ip_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* parse an ethernet packet to a query */
void parse_to_query(unsigned char * packet, int len, query * q_store);

#endif
