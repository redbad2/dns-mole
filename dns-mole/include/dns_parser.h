#ifndef DNSM_DNS_PARSER_H
#define DNSM_DNS_PARSER_H

void dns2query(u_char * packet, int len, query * q_store);
void skip_question_section(int qc, u_char * packet);
void get_domain_name(u_char ** dname, char * dst_name);
void skip_name(u_char ** dname);
int get_dns_value(u_char * value_place, u_char * dns_place, u_char ** dst, int len);

#endif 
