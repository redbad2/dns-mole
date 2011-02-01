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
 
#ifndef DNSM_DNS_PARSER_H
#define DNSM_DNS_PARSER_H

int dns2query(unsigned char * packet, int len, query * q_store, int dl_len);
void get_type(unsigned char *,query *);
int extract_name(unsigned char *, unsigned char *, char *);
int extract_query_section(unsigned char *, unsigned char *, query *);
int extract_rr(unsigned char *, unsigned char *, responseSection );
int check_domain_name(char *);

#endif 
