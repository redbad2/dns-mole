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

#include <stdlib.h>
#include "../include/dnsmole.h"
#include "../include/ip_list.h"

ip_list *ip_new(unsigned int ip, char *name,int level){
    ip_list *new;

    if((new = (ip_list *) malloc(sizeof(ip_list))) != NULL){
        new->ip = ip;
        new->prev = new->next = NULL;
        new->q_domains = new_domain(name,level);
        new->sum = new->num = 0;         
        return new;
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

domains *new_domain(char *name,int level){
    domains *temp_domain;
    
    if((temp_domain = (domains *) malloc(sizeof(domains))) != NULL){
        temp_domain->next = temp_domain->prev = NULL;
        temp_domain->count = 1;
        if((temp_domain->d_name = malloc(strlen(name) * sizeof(char) +1)) == NULL){
           fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE); 
        }
        memcpy(temp_domain->d_name,name,strlen(name)+1);
        temp_domain->level = level;
        return temp_domain;
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void ip_remove(ip_list *ip){
    domains *loop_domain = ip->q_domains;
    
    while(loop_domain){
        free(loop_domain->d_name);
        loop_domain = loop_domain->next;
        free(loop_domain->prev);
    }

    ip->prev->next = ip->next;
    ip->next->prev = ip->prev;
    free(ip);
}

ip_list *search_ip(ip_list *ip_structure,unsigned int ip){
    
    ip_list *loop_ip = ip_structure;
    
    while(loop_ip){
        if(ip_structure->ip == ip)
           return ip_structure;

        loop_ip = loop_ip->next;
    }
    return (ip_list *) 0;
}

void ip_add_domain(ip_list *ip,char *name,int level){
    domains *temp_domain = ip->q_domains;
    
    while(temp_domain->next)
        temp_domain = temp_domain->next;

    temp_domain->next = new_domain(name,level);
    temp_domain->next->prev = temp_domain;
}

void ip_remove_domain(ip_list *ip,char *name){
    domains *temp_domain = ip->q_domains;

    while(temp_domain){
        if(!strcmp(temp_domain->d_name,name)){
            temp_domain->prev->next = temp_domain->next;
            temp_domain->next->prev = temp_domain->prev;
            free(temp_domain->d_name);
            free(temp_domain);
        }

        temp_domain = temp_domain->next;
    }
}

int return_count(ip_list *ip,char *name){
    domains *temp_domain = ip->q_domains;

    while(temp_domain){
        if(!strcmp(temp_domain->d_name,name))
            return temp_domain->count;

        temp_domain = temp_domain->next;
    }

    return 0;
}

void add_count(ip_list *ip,char *name){
    domains *temp_domain = ip->q_domains;

    while(temp_domain){
        if(!strcmp(temp_domain->d_name,name))
           temp_domain->count++;
        
        temp_domain = temp_domain->next;
    }
}

    




