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
	
	// set src ip
	q_store->q_srcip = iphdr->ip_src;

	u_char * data = (u_char *)(dqhdr + sizeof(struct dns_query_header));
	
	int qnum = ntohs(dqhdr->dq_qc);
	int anum = ntohs(dqhdr->dq_ac);
	// set answer number
	q_store->q_ansnum = anum;
	
	int size = get_url_size(data);
	data += extract_question(data, q_store);
	q_store->q_answers = malloc(anum * sizeof(answer));
	data += extract_answers(data, (u_char *)dqhdr, anum, q_store);
	
	if (qnum > 1) {
		// to do
		// if questions number > 1 then
	}
}

int get_url_size(u_char * data) {
	int i = 0;
	int toskip = data[0];

	while(toskip != 0){
		i += toskip + 1;
		toskip = data[i];
	}

	return i + 1;
}

int extract_question(u_char * data, query * q) {
	return get_url(data, q->q_dname);
}

int extract_answers(u_char * data, u_char * start, int num, query * q) {
	int i;
	int size = 0;
	for	(i = 0; i < num; i++) {
		struct static_RR * rr = (struct static_RR *)data;
		q->q_answers[i].ttl = ntohl(rr->r_ttl);
		q->q_answers[i].type = ntohs(rr->r_type);
		data += sizeof(struct static_RR);
		extract_value(data, start, q->q_answers[i].type, &q->q_answers[i].value, ntohs(rr->r_rdlength));
		data += ntohs(rr->r_rdlength);
		size += sizeof(struct static_RR) + ntohs(rr->r_rdlength);
	}
	return size;
}

void extract_value(u_char * data, u_char * start, int type, u_char ** dst, int length) {
	u_char * value = (*dst);
	switch (type) {
	case RR_TYPE_A:
		value = (u_char *)malloc(5);
		strncpy(value, data, 4);
		return;
	case RR_TYPE_NS:
	case RR_TYPE_CNAME:
	case RR_TYPE_PTR:{
		u_char * temp_val = (u_char *)malloc(MAX_LENGTH);
		int value_size = get_dns_value(data, start, &temp_val, length);
		value = (u_char *)malloc(value_size);
		strcpy(value, temp_val);
		free(temp_val);
		return;
		}
	case RR_TYPE_MX: {
		u_char * temp_val = (u_char *)malloc(MAX_LENGTH);
		int value_size = get_dns_value(data + 2, start, &temp_val, length);
		value = (u_char *)malloc(value_size + 2);
		value[0] = data[0];
		value[1] = data[1];
		strcpy(&value[2], temp_val);
		free(temp_val);
		return;
		}
	default:
		// error
		return;
	}
}

int get_url(u_char * data, u_char * dst) {
	int i = 1;
	int toread = data[0];
	int start = 1;
	int j = 0;
	
	while (toread != 0) {
		for (; i < toread + start; i++)
			dst[j++] = data[i];
		dst[j++] = '.';
		toread = data[i++];
		start = i;
	}
	dst[j - 1] = '\0';
	return i;
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
