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

#include "dnsmole.h"

int dns2query(u_char *packet, int len, query * q_store,int dl_len) {
    
    struct ip_header * iphdr; 
    struct dns_query_header *dqhdr;
    u_char *data, *dns_start; 
    int count;
    
    iphdr = (struct ip_header *) (packet + sizeof(struct ether_header)); 
    dqhdr = (struct dns_query_header *)(packet + dl_len + iphdr->ip_ihl * 4 + sizeof(struct udp_header));
    data = (u_char *)(packet + dl_len + iphdr->ip_ihl * 4 + sizeof(struct udp_header) + sizeof(struct dns_query_header));
    dns_start = data - sizeof(struct dns_query_header);
    
    q_store->srcip = iphdr->ip_src;
    q_store->dstip = iphdr->ip_dst;
	
    q_store->is_answer = dqhdr->qr;
    
    if((dqhdr->rcode) == 0x1)
        q_store->is_nxdomain = 1;
    else
        q_store->is_nxdomain = 0;

    if(dqhdr->rcode || !q_store->is_nxdomain)
	    return 0;
		
    q_store->qnum = ntohs(dqhdr->dq_qc);
    q_store->ansnum = ntohs(dqhdr->dq_ac);
    q_store->nsnum = ntohs(dqhdr->dq_nc);
    q_store->addnum = ntohs(dqhdr->dq_arc);
    
    q_store->answers = (responseSection *) malloc(q_store->ansnum * sizeof(struct responseSection));
    q_store->authority = (responseSection *) malloc(q_store->nsnum * sizeof(struct responseSection));
    q_store->additional = (responseSection *) malloc(q_store->addnum * sizeof(struct responseSection));
	
    memset(q_store->dname,'\0',MAX_LENGTH);
    data += extract_query_section(data,dns_start,q_store);
   
    if(!check_domain_name(q_store->dname))
	    return 0;
    
    if(q_store->is_nxdomain || q_store->is_answer)
        return 1;

    if(q_store->qnum > 1) // More the one question in packet, unsupported ATM
	    return 0;
   
    for(count = 0; count < q_store->ansnum; count++)
	    data += extract_rr(data,dns_start,q_store->answers[count]);
		
    for(count = 0; count < q_store->nsnum; count++)
	    data += extract_rr(data,dns_start,q_store->authority[count]);
		
    for(count = 0; count < q_store->addnum; count++)
	    data += extract_rr(data,dns_start,q_store->additional[count]);
    
    return 1;
}

int extract_query_section(unsigned char * data, unsigned char *beginning, query *q){
    int name_size = 0;
	
    name_size = extract_name(data,beginning,q->dname);
    get_type(data+name_size,q);
    return (name_size+4);
}

void get_type(unsigned char *data, query *q){
	
    q->q_type = *(data);
    q->q_type = q->q_type << 8;
    q->q_type |= *(data+1);
}

int extract_name(unsigned char *data, unsigned char *beginning, char *name){
    int count,offset_copy,inner_loop,exit_now = 1;
    char readChr;
	
    count = strlen(name);
    while(*data && exit_now){
	if(((*data >> 6) == 0x03) ){
	    offset_copy = *data & 0x3f;
	    offset_copy = offset_copy << 8;
	    offset_copy |= *(data+1);	
	    extract_name(beginning+offset_copy,beginning,name);
	    data+=2; exit_now = 0;
	}
	else{
	    readChr = *data++;
	    for(inner_loop = 0; inner_loop < (int)readChr; inner_loop++)
		name[count++] = *data++;
			
	    if(*data)
		name[count++] ='.';	
	}
    }
	
    count+=2;
    return count;
}

int extract_rr(unsigned char *data, unsigned char *start, responseSection rS) {
    struct static_RR *rr;
    int count,ip_count;
	
    memset(rS.name,'\0',MAX_LENGTH);
    memset(rS.value,'\0',MAX_LENGTH);
	
    count = extract_name(data,start,rS.name);
    rr = (struct static_RR *)(data + count);
    data += sizeof(struct static_RR)- 2 + count;
    count += sizeof(struct static_RR) - 2;
    rS.ttl = ntohl(rr->r_ttl);
    rS.type = ntohs(rr->r_type);
    
    switch(rS.type){
	case RR_TYPE_A:
	    rS.ip = 0;
	    for(ip_count = 0; ip_count < 3; ip_count++){
		rS.ip |= *(data+ip_count); 
		rS.ip = rS.ip << 8;
	    }
	    rS.ip |= *(data+ip_count);
	    data+=4;
	    break;
			
	case RR_TYPE_CNAME:
	case RR_TYPE_NS:
	case RR_TYPE_PTR:
	    data += extract_name(data,start,rS.value);
	    break;
			
	case RR_TYPE_MX:
	    data += 2; count+=2;
	    data += extract_name(data,start,rS.value);
	    break;
    }
	
    count += ntohs(rr->r_rdlength);
    return count;
}

int check_domain_name(char *domain){
    int domain_size = strlen(domain);
    int lookup;
    if(!(*domain)){
	    memcpy(domain,"<Root>",7);
    }
    else{
	for(lookup = 0; lookup < domain_size; lookup++){
	    if(isalpha(domain[lookup]) || isdigit(domain[lookup]) || (domain[lookup] == '.') ||  (domain[lookup] == '-')){
		    if((domain[lookup] == '.') && domain[lookup+1] == '-'){
		        return 0;
		    }
	    } else 
		    return 0;
        }
    }
    
    for(lookup = 0; lookup < domain_size; lookup++)
            domain[lookup] = (isupper(domain[lookup]) ? tolower(domain[lookup]): domain[lookup]);

    return 1;
}


