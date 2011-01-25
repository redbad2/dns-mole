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
int dns2query(u_char * packet, int len, query * q_store,int dl_len) {
    
    struct ip_header * iphdr = (struct ip_header *) (packet + sizeof(struct ether_header)); 
    struct dns_query_header *dqhdr;
    u_char * data; 
    
    dqhdr = (struct dns_query_header *)(packet + dl_len + iphdr->ip_ihl * 4 + sizeof(struct udp_header));
    data = (u_char *)(packet + dl_len + iphdr->ip_ihl * 4 + sizeof(struct udp_header) + sizeof(struct dns_query_header));
	
    // set src ip
    q_store->srcip = iphdr->ip_src;
    q_store->dstip = iphdr->ip_dst;
	
    q_store->is_answer = dqhdr->qr;
    
    int qnum = ntohs(dqhdr->dq_qc);
    int anum = ntohs(dqhdr->dq_ac);

    // set answer number
    q_store->ansnum = anum;
	
    //int size = get_url_size(data);

    data += extract_question(data,q_store); 

    q_store->q_type = *(data);
    q_store->q_type = q_store->q_type << 8;
    q_store->q_type |= *(data+1);
   
    data += 4;

    if(anum == 0)
    	return 1;

    q_store->answers = malloc(anum * sizeof(answer));
    data += extract_answers(data, (u_char *)dqhdr, anum, q_store);
	
    if(qnum > 1) {
	    // to do
	    // if questions number > 1 then
    }

    return 1;
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
	return get_url(data, (u_char *)q->dname);
}

int extract_answers(u_char * data, u_char * start, int num, query * q) {
	int i;
	int size = 0;
	for(i = 0; i < num; i++) {
		while ((*data) != 0) {
			if (((*data) & 0xC0) == 0XC0) {
				data += 2;
				size += 2;
				break;
			}
			else {
				size++;
				data++;
			}
		}
		struct static_RR * rr = (struct static_RR *)data;
		q->answers[i].ttl = ntohl(rr->r_ttl);
		q->answers[i].type = ntohs(rr->r_type);
		data += sizeof(struct static_RR) - 2;
		extract_value(data, start, q->answers[i].type, &q->answers[i].value, ntohs(rr->r_rdlength));
		data += ntohs(rr->r_rdlength);
		size += sizeof(struct static_RR) + ntohs(rr->r_rdlength);
	}
	return size;
}

void extract_value(u_char *data, u_char *start, int type, u_char **dst, int length) {
	
    switch (type) {
	    case RR_TYPE_A:
		    (*dst) = (u_char *)malloc(5);
		    strncpy((*dst), data, 4);
	        break;

	    case RR_TYPE_NS:
	    case RR_TYPE_CNAME:
	    case RR_TYPE_PTR:{
		    u_char * temp_val = (u_char *)malloc(MAX_LENGTH);
		    int value_size = get_dns_value(data, start, &temp_val, length);
		    (*dst) = (u_char *)malloc(value_size);
		    strcpy((*dst), temp_val);
		    free(temp_val);
		    break; 
            }
		    
	    case RR_TYPE_MX: {
		    u_char * temp_val = (u_char *)malloc(MAX_LENGTH);
		    int value_size = get_dns_value(data + 2, start, &temp_val, length);
		    (*dst) = (u_char *)malloc(value_size + 2);
		    (*dst)[0] = data[0];
		    (*dst)[1] = data[1];
		    strcpy(&(*dst)[2], temp_val);
		    free(temp_val);
		    break;
            }
	    default:
		    break;
	}
}

int get_url(u_char * data, u_char * dst) {
	int i = 1;
	int toread = data[0];
	int start = 1;
	int j = 0;
	
	while(toread != 0 ) {
		for (; i < toread + start; i++)
                dst[j++] = (isupper(data[i]) ? tolower(data[i]): data[i]);

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
	unsigned short size;
	for (; i < len;) {
		if ((value_place[i] & 0xC0) == 0xC0) {
			size = ntohs(*((unsigned short *)(&value_place[i]))) & 0x3FFF;
			k = 0;
			while (1) {
				if (dns_place[size + k] == '\0') {
					val[j++] = '\0';
					i += 2;
					break;
				}
				else if ((dns_place[size + k] & 0xC0) == 0xC0) {
					size = ntohs(*((unsigned short *)(&dns_place[size + k]))) & 0x3FFF;
					k = 0;
					continue;
				}
				else {
					val[j] = dns_place[size + k];
					j++;
					k++;
				}
			}
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
