/* query.c
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

#include "../include/dnsmole.h"

query_domain *new_query_domain(char *name){
    query_domain *t_q_domain;

    if((t_q_domain = (query_domain *) malloc(sizeof(query_domain))) != NULL){
        if((t_q_domain->name = malloc(strlen(name) * sizeof(char) + 1)) != NULL){
            t_q_domain->prev =  t_q_domain->next = NULL;
            t_q_domain->ip = NULL;
            t_q_domain->type = 0.0;
            memcpy(t_q_domain->name,name,strlen(name) +  1);
            return t_q_domain;
        }
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void add_ip_2_domain(query_domain *main,ip_list *ip){
    d_2_ip *t_s;
    
    if(main == NULL)

        main->ip = ip;

    else{

        t_s = main->ip;

        while(t_s){
            
            if(t_s->ip->ip == ip->ip){
                t_s->count++;
                return;
            }

            t_s = t_s->next;
        }

        if(t_s == NULL){

            if((t_s = (d_2_ip *) malloc(sizeof(d_2_ip))) == NULL){
                fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
            }
            else{
                t_s->ip = ip;
                t_s->next = main->ip;
                t_s->prev = NULL;
                t_s->count = 1;
                main->ip = t_s;
            }
        }
    }
}

query_domain *find_by_name(query_domain *start,char *name){
    query_domain *temp_domain = start;

    while(start){
        if(!strcmp(temp_domain->name,name))
            return temp_domain;

        temp_domain = temp_domain->next;
    }

    return (query_domain *) 0;
}

void free_ip_in_domain(d_2_ip *temp){
    
    if(temp){
        free_ip_in_domain(temp->next);
        free(temp);
    }
}


void remove_domain(query_domain *dom){

    remove_ip_in_domain(dom->ip);
    free(name);
    dom->prev->next = dom->next;
    dom->next->prev = dom->prev;
    free(dom);
}




