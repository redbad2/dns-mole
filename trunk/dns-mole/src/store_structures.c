/* store_structures.c
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

domain_store *new_domain(const char *name,float type){
    domain_store *t_domain_store;

    if((t_domain_store = (domain_store *) malloc(sizeof(domain_store))) != NULL){
        if((t_domain_store->d_name = malloc(strlen(name) * sizeof(char) + 1)) != NULL){
            t_domain_store->next = t_domain_store->prev = NULL;
            t_domain_store->domain_ip = NULL;
            t_domain_store->type = type;
            t_domain_store->queried_overall = 0;
            t_domain_store->queried_with_different_ip = 0;
            memcpy(t_domain_store->d_name,name,strlen(name)+1);
            return t_domain_store;
        }
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void add_ip_to_domain(domain_store *q,ip_store *t_ip_store){
    domain_ip_store *t_s;
    
    q->queried_overall++;
    
    if(q->domain_ip == NULL){
        
        if((t_s = (domain_ip_store *) malloc(sizeof(domain_ip_store))) == NULL){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        q->queried_with_different_ip++;
        t_s->ip = t_ip_store;
        t_s->count = 1;
        t_s->next = t_s->prev = NULL;
        q->domain_ip = t_s;
    }

    else{

        t_s = q->domain_ip;

        while(t_s){
            
            if(t_s->ip->ip == t_ip_store->ip){
                t_s->count++;
                return;
            }
	
            t_s = t_s->next;
        }

        if(t_s == NULL){

            if((t_s = (domain_ip_store *) malloc(sizeof(domain_ip_store))) == NULL){
                fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
            }
           
            q->queried_with_different_ip++;
            t_s->ip = t_ip_store;
            t_s->next = q->domain_ip;
            //q->domain_ip->prev = t_s;
            t_s->prev = NULL;
            t_s->count = 1;
            q->domain_ip = t_s;
        }
    }
}

domain_store *find_domain(domain_store *q,const char *name){
    domain_store *start_domain = q;
    
    while(start_domain){
        if(!memcmp(start_domain->d_name,name,strlen(name)))
            return start_domain;

        start_domain = start_domain->next;
    }

    return (domain_store *) 0;
}

void remove_ip_in_domain(domain_ip_store *q){
    if(q){
        remove_ip_in_domain(q->next);
        free(q);
    }
}
	

void remove_domain(domain_store *q, int clean_type){

    if(q){
        printf("(%s) %p - ( %p , %p)\n",q->d_name,q,q->domain_ip,q->next);
	    printf("\t\t\t\t %p\n",q->domain_ip);	

        if(clean_type){
            remove_domain(q->next,1);
            q->prev = q->next = NULL;
        }else{
            if(q->prev && q->next){
	            q->prev->next = q->next;
	            q->next->prev = q->prev;
            }
            if(q->prev && !q->next)
                q->prev->next = NULL;
        
            if(!q->prev && q->next)
                q->next->prev = NULL;
            
        }
        remove_ip_in_domain(q->domain_ip->next);
        free(q->domain_ip);
        q->domain_ip = NULL;
        free(q->d_name);
        free(q);
    }
}

ip_store *new_ip(unsigned int ip){
    ip_store *t_ip_store;

    if((t_ip_store = (ip_store *) malloc(sizeof(ip_store))) != NULL){
        t_ip_store->ip = ip;
        t_ip_store->black_hosts = 0;
        t_ip_store->all_hosts = 0;
        t_ip_store->white_hosts = 0;
        t_ip_store->next = t_ip_store->prev = NULL;
        return t_ip_store;
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

domain_ip_store *find_ip_in_domain(domain_ip_store *q,unsigned int ip){
    
    domain_ip_store *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip->ip == ip)
           return loop_ip;

        loop_ip = loop_ip->next;
    }
    return (domain_ip_store *) 0;
}

ip_store *find_ip(ip_store *q,unsigned int ip){
    
    ip_store *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip == ip){
           return loop_ip; 
        }

        loop_ip = loop_ip->next;
    }
    return (ip_store *) 0;
}

void remove_ip(ip_store *q){
    
    if(q){
        remove_ip(q->next);
        free(q);
    }
}
