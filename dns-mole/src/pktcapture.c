/* pktcapture.c
 *
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

#include "../include/pktcapture.h"
#include "../include/error.h"
#include <time.h>
#include <pcap.h>
#include "../include/query.h"


/*
 * main packet capture loop
 * interface -- the device you want to touch, set NULL if you want
 *              to use pcap_lookupdev
 * count     -- number of packets
 *              -1 for infinite
 *              0 for until error
 */
int packet_capture_loop(char * interface, int count) {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid()) {
		return PCAP_ROOT_ERROR;
	}

	/* look up device */
	if (interface == NULL) {
		dev = pcap_lookupdev(errbuf);
	}
	else dev = interface;
	if (dev == NULL) {
		return PCAP_LOOKUPDEV_ERROR;
	}

	/* ask pcap for the network address and mask of the device */
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* open device for reading */
	pcap_t * descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (descr == NULL) {
		return PCAP_OPEN_LIVE_ERROR;
	}

	/* compile the program */
	struct bpf_program filter;
	if (pcap_compile(descr, &filter, DNS_QUERY_FILTER, 0, netp) == -1) {
		return PCAP_COMPILE_ERROR;
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(descr, &filter) == -1) {
		return PCAP_SETFILTER_ERROR;
	}

	/* loop */
	pcap_loop(descr, count, pcap_callback, NULL);

	return 0;
}

/*
 * handle every packet captured
 */
void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	unsigned short type = get_ethernet_type(args, pkthdr, packet);
	switch (type) {
	case ETHERTYPE_IP:
		ip_handler(args, pkthdr, packet);
		break;
	default:break;
	};
}

/*
 * get type of ethernet packet, e.g. IP, ARP
 */
unsigned short get_ethernet_type (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	unsigned int length = pkthdr->len;
	struct ether_header * ehdr;
	unsigned short ether_type;
	ehdr = (struct ether_header *) packet;
	ether_type = ntohs(ehdr->ether_type);
	return ether_type;
}

/*
 * parse ip packet to query
 */
void ip_handler (u_char * args, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	query * q = (query *)malloc(sizeof(query));
	memset(q, 0, sizeof(query));
	parse_to_query(packet, q);
	q->q_time = pkthdr->ts;
	qlist_insert(q);
}


void parse_to_query(unsigned char * packet, query * q_store) {
	struct ip_header * ih = (struct ip_header *) (packet + sizeof(struct ether_header));
	struct dns_query_header * dqh;
	if (ih->ip_proto == IP_PROTOCOL_TCP) {
		dqh = (struct dns_query_header *)(packet + sizeof(struct ether_header) + ih->ip_ihl * 4 + sizeof(struct tcp_header));
	}
	else if (ih->ip_proto == IP_PROTOCOL_UDP) {
		dqh = (struct dns_query_header *)(packet + sizeof(struct ether_header) + ih->ip_ihl * 4 + sizeof(struct udp_header));
	}
	q_store->q_srcip = ih->ip_src;
	//q_store->q_time = time(NULL);


/*
 * Resource Record format(Answer section)
 * 0                16                32
 * +--------+--------+--------+--------+
 * |                                   |
 * ~               NAME                ~
 * |                                   |
 * +--------+--------+--------+--------+
 * |      TYPE       |      CLASS      |
 * +--------+--------+--------+--------+
 * |                TTL                |
 * +--------+--------+--------+--------+
 * | DATA LENGTH     |                 |
 * +-----------------+                 +
 * |                                   |
 * ~             DATA                  ~
 * |                                   |
 * +-----------------------------------+
 */
	char * dname;
	if (ih->ip_proto == IP_PROTOCOL_TCP) {
		dname = (char *)(packet	+ ih->ip_ihl * 4 + sizeof(struct tcp_header)
				+ sizeof(struct ether_header) + sizeof(struct dns_query_header));
	}
	else if (ih->ip_proto == IP_PROTOCOL_UDP) {
		dname = (char *)(packet	+ ih->ip_ihl * 4 + sizeof(struct udp_header)
				+ sizeof(struct ether_header) + sizeof(struct dns_query_header));
	}

	dname++;
	char name[MAX_LENGTH];
	int i = 0;
	char t;
	for (; (*dname) != 0; dname++) {
		t = (*dname);
		if ((t >= 'a' && t <= 'z') || (t >= 'A' && t <= 'Z')
				|| (t >= '0' && t <= '9') || (t == '-')) {
			name[i++] = t;
		}
		else name[i++] = '.';
	}
	name[i] = '\0';
	strcpy(q_store->q_dname, name);

	if (i % 4 != 0)
		dname += 4 - (i % 4);
	dname += 5;

	int count = 0;
	while ((*dname) != 0) {
		count++;
		dname++;
	}
	count++;
	if (count % 4 != 0)
		dname += 4 - (count % 4);
	dname += 5;

	q_store->q_type = ntohs(*((unsigned short *)dname));

	dname += 4;
	q_store->q_ttl = ntohl(*((unsigned int *)dname));

	dname += 4;
	unsigned short dlen = ntohs(*((unsigned short *)dname));

	q_store->q_value = (char *)malloc(dlen);
	strcpy(q_store->q_value, dname + 2);
}
