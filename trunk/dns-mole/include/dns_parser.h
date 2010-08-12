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

int dns2query(u_char * packet, int len, query * q_store, int dl_len);
int get_url_size(u_char * data);
int extract_question(u_char * data, query * q);
int extract_answers(u_char * data, u_char * start, int num, query * q);
void extract_value(u_char * data, u_char * start, int type, u_char ** dst, int length);
int get_url(u_char * data, u_char * dst);
int get_dns_value(u_char * value_place, u_char * dns_place, u_char ** dst, int len);

#endif 
