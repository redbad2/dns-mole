/* bl_detection_structure.c
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

bl_domain *new_bl_domain(const char *name,float type){
    bl_domain *t_bl_domain;

    if((t_bl_domain = (bl_domain *) malloc(sizeof(bl_domain))) != NULL){
        if((t_bl_domain->d_name = malloc(strlen(name) * sizeof(char) + 1)) != NULL){
            t_bl_domain->next = t_bl_domain->prev = NULL;
            t_bl_domain->domain_ip = NULL;
            t_bl_domain->type = type;
            t_bl_domain->queried_overall = 0;
            memcpy(t_bl_domain->d_name,name,strlen(name)+1);
            return t_bl_domain;
        }
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void add_ip_to_domain(bl_domain *q,bl_ip *t_bl_ip){
    bl_domain_ip *t_s;
    
    q->queried_overall++;
    
    if(q->domain_ip == NULL){
        
        if((t_s = (bl_domain_ip *) malloc(sizeof(bl_domain_ip))) == NULL){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        
        t_s->ip = t_bl_ip;
        t_s->count = 1;
        t_s->next = t_s->prev = NULL;
        q->domain_ip = t_s;
    }

    else{

        t_s = q->domain_ip;

        while(t_s){
            
            if(t_s->ip->ip == t_bl_ip->ip){
                t_s->count++;
                return;
            }
	
            t_s = t_s->next;
        }

        if(t_s == NULL){

            if((t_s = (bl_domain_ip *) malloc(sizeof(bl_domain_ip))) == NULL){
                fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
            }
           
            t_s->ip = t_bl_ip;
            t_s->next = q->domain_ip;
            q->domain_ip->prev = t_s;
            t_s->prev = NULL;
            t_s->count = 1;
            q->domain_ip = t_s;
        }
    }
}

bl_domain *find_domain(bl_domain *q,const char *name){
    bl_domain *start_domain = q;
    
    while(start_domain){
        if(!strcmp(start_domain->d_name,name))
            return start_domain;

        start_domain = start_domain->next;
    }

    return (bl_domain *) 0;
}

void remove_ip_in_domain(bl_domain_ip *q){
    if(q){
        remove_ip_in_domain(q->next);
	free(q);
    }
}
	

void remove_domain(bl_domain *q, int clean_type){

    if(q){
        remove_ip_in_domain(q->domain_ip);
		
	if(clean_type){
	    remove_domain(q->next,1);
	}
	else{
	    q->prev->next = q->next;
	    q->next->prev = q->prev;
	}
        free(q);
    }
}

bl_ip *new_bl_ip(unsigned int ip){
    bl_ip *t_bl_ip;

    if((t_bl_ip = (bl_ip *) malloc(sizeof(bl_ip))) != NULL){
        t_bl_ip->ip = ip;
        t_bl_ip->black_hosts = 0;
        t_bl_ip->all_hosts = 0;
        t_bl_ip->white_hosts = 0;
        return t_bl_ip;
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

bl_domain_ip *find_ip_in_domain(bl_domain_ip *q,unsigned int ip){
    
    bl_domain_ip *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip->ip == ip)
           return loop_ip;

        loop_ip = loop_ip->next;
    }
    return (bl_domain_ip *) 0;
}

bl_ip *find_ip(bl_ip *q,unsigned int ip){
    
    bl_ip *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip == ip)
           return loop_ip;

        loop_ip = loop_ip->next;
    }
    return (bl_ip *) 0;
}

void remove_ip(bl_ip *q){
    if(q){
        remove_ip(q->next);
        free(q);
    }
}
