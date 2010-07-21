/* dns_parser.h
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

#include <stdlib.h>
#include <string.h>
#include "../include/query.h"
#include "../include/dns_sniffer.h"
#include "../include/dns_parser.h"

/* parse an DNS packet to a query */

void dns2query(u_char * packet, int len, query * q_store) {
	struct ip_header * iphdr = (struct ip_header *) (packet + sizeof(struct ether_header));
	struct dns_query_header * dqhdr;
	if (iphdr->ip_proto == IP_PROTOCOL_TCP) {
		dqhdr = (struct dns_query_header *)(packet + sizeof(struct ether_header) + iphdr->ip_ihl * 4 + sizeof(struct tcp_header));
	}
	else if (iphdr->ip_proto == IP_PROTOCOL_UDP) {
		dqhdr = (struct dns_query_header *)(packet + sizeof(struct ether_header) + iphdr->ip_ihl * 4 + sizeof(struct udp_header));
	}
	q_store->q_srcip = iphdr->ip_src;
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
	u_char * dname;
	if (iphdr->ip_proto == IP_PROTOCOL_TCP) {
		dname = (char *)(packet	+ iphdr->ip_ihl * 4 + sizeof(struct tcp_header) + sizeof(struct ether_header) + sizeof(struct dns_query_header));
	}
	else if (iphdr->ip_proto == IP_PROTOCOL_UDP) {
		dname = (char *)(packet	+ iphdr->ip_ihl * 4 + sizeof(struct udp_header) + sizeof(struct ether_header) + sizeof(struct dns_query_header));
	}
	
	u_char name[MAX_LENGTH];
	dname++;
	get_domain_name(&dname, name);
	dname += 4;
	strcpy(q_store->q_dname, name);

	if (ntohs(dqhdr->dq_qc) > 1) {
		skip_question_section(dqhdr->dq_qc, dname);
	}
	
	skip_name(&dname);
	if (DQH_QR(dqhdr) == 0)
		return;
		
	q_store->q_type = ntohs(*((unsigned short *)dname));
	dname += 4;
	q_store->q_ttl = ntohl(*((unsigned int *)dname));
	dname += 4;
	
	
	unsigned short rs_data_len = ntohs(*((unsigned short *)dname));
	dname += 2;
	switch (q_store->q_type) {
	case RR_TYPE_A:
		q_store->q_value = (char *)malloc(5);
		strncpy(q_store->q_value, dname, 4);
		return;
	case RR_TYPE_NS:
	case RR_TYPE_CNAME:
	case RR_TYPE_PTR:{
		u_char * value = (u_char *)malloc(MAX_LENGTH);
		int value_size = get_dns_value(dname, (u_char *)dqhdr, &value, rs_data_len);
		q_store->q_value = (char *)malloc(value_size);
		strcpy(q_store->q_value, value);
		free(value);
		return;
		}
	case RR_TYPE_MX: {
		u_char * value = (u_char *)malloc(MAX_LENGTH);
		int value_size = get_dns_value(dname + 2, (u_char *)dqhdr, &value, rs_data_len);
		q_store->q_value = (char *)malloc(value_size + 2);
		q_store->q_value[0] = (*dname);
		dname++;
		q_store->q_value[1] = (*dname);
		strcpy(&q_store->q_value[2], value);
		free(value);
		return;
		}
	default:
		// error
		return;
	}
}

void skip_question_section(int qc, u_char * packet) {
	while (qc > 0) {
		qc--;
		while ((*packet) != 0)
			packet++;
		packet++;
		packet += 4;
	}
}

void get_domain_name(u_char ** dname, char * dst_name) {
	int i = 0;
	char t;
	for (; (**dname) != 0; (*dname)++) {
		t = (**dname);
		if ((t >= 'a' && t <= 'z') || (t >= 'A' && t <= 'Z')
				|| (t >= '0' && t <= '9') || (t == '-')) {
			dst_name[i++] = t; 
		}
		else dst_name[i++] = '.';
	}
	dst_name[i] = '\0';
	(*dname)++;
}

void skip_name(u_char ** dname) {
	if ((**dname) == 0xC0) {
		(*dname) += 2;
		return;
	}
	else if ((**dname) != 0) {
		(*dname)++;
		skip_name(&(*dname));
	}
	else {
		(*dname)++;
		return;
	}
}

int get_dns_value(u_char * value_place, u_char * dns_place, u_char ** dst, int len) {
	u_char * val = (*dst);
	int i = 0, j = 0, k = 0;
	int size;
	for (; i < len;) {
		if ((value_place[i] & 0xC0) == 0xC0) {
			size = ntohs(*((unsigned short *)(&value_place[i]))) & 0x3F;
			k = 0;
			while (dns_place[size + k] != '\0') {
				val[j] = dns_place[size + k];
				j++;
				k++;
			}
			val[j++] = '\0';
			i += 2;
		}
		else {
			val[j++] = value_place[i++];
		}
	}
	for (i = 0; i < j; i++) {
		if ((val[i] >= 'a' && val[i] <= 'z') || (val[i] >= 'A' && val[i] <= 'Z')
				|| (val[i] >= '0' && val[i] <= '9') || (val[i] == '-')) {
			continue;
		}
		else if(val[i] != '\0')
			val[i] = '.';
	}
	if (val[0] == '.') {
		strcpy(val, &val[1]);
		return j - 1;
	}
	else return j;
}
