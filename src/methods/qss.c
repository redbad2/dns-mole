/* qss.c
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
 
#include "qss.h"

qss_domain *new_domain(const char *name,float type){
    qss_domain *t_qss_domain;

    if((t_qss_domain = (qss_domain *) malloc(sizeof(qss_domain))) != NULL){
        if((t_qss_domain->d_name = malloc(strlen(name) * sizeof(char) + 1)) != NULL){
            t_qss_domain->next = t_qss_domain->prev = NULL;
            t_qss_domain->domain_ip = NULL;
            t_qss_domain->type = type;
            t_qss_domain->queried_overall = 0;
            t_qss_domain->queried_with_different_ip = 0;
            memcpy(t_qss_domain->d_name,name,strlen(name)+1);
            return t_qss_domain;
        }
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void add_domain_to_list(void **d_head, void **d_rear,void *t_qry, void *t_ip,int t_type){
	
    qss_domain *head = (qss_domain *)*d_head;
    qss_domain *rear = (qss_domain *)*d_rear;
    query *t_query = (query *) t_qry;
    qss_ip *t_ip_store = (qss_ip *) t_ip;
	
    qss_domain *t_domain_store = NULL;

    if(head == NULL){
	    head = rear = new_domain(t_query->dname,t_type);
	    add_ip_to_domain(rear,(void *)t_ip_store);   
    }
    else{
	    if((t_domain_store = find_domain(head,t_query->dname))){
	        add_ip_to_domain(t_domain_store,(void *)t_ip_store);
	    } 
        else {
	        t_domain_store = new_domain(t_query->dname,t_type);
	        add_ip_to_domain(t_domain_store,(void *)t_ip_store);
	        t_domain_store->prev = rear;
    	    rear->next = t_domain_store;
        	rear = rear->next;
        }
    }
    
    *d_head = head;
    *d_rear = rear;
}

void add_ip_to_domain(qss_domain *q,qss_ip *t_qss_ip){
    qss_domain_ip *qss_temp_dip;
    
    q->queried_overall++;
    
    if(q->domain_ip == NULL){
        
        if((qss_temp_dip = (qss_domain_ip *) malloc(sizeof(qss_domain_ip))) == NULL){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        q->queried_with_different_ip++;
        qss_temp_dip->ip = t_qss_ip;
        qss_temp_dip->count = 1;
        qss_temp_dip->next = qss_temp_dip->prev = NULL;
        q->domain_ip = qss_temp_dip;
    }

    else{
        qss_temp_dip = q->domain_ip;

        while(qss_temp_dip){
            
            if(qss_temp_dip->ip->ip == t_qss_ip->ip){
                qss_temp_dip->count++;
                return;
            }
	
            qss_temp_dip = qss_temp_dip->next;
        }

        if(qss_temp_dip == NULL){

            if((qss_temp_dip = (qss_domain_ip *) malloc(sizeof(struct qss_domain_ip))) == NULL){
                fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
            }
           
            q->queried_with_different_ip++;
            qss_temp_dip->ip = t_qss_ip;
            qss_temp_dip->next = q->domain_ip;
            qss_temp_dip->prev = NULL;
            qss_temp_dip->count = 1;
            q->domain_ip = qss_temp_dip;
        }
    }
}

qss_domain *find_domain(qss_domain *q,const char *name){
    qss_domain *start_domain = q;
    
    while(start_domain != NULL){
        if(!memcmp(start_domain->d_name,name,strlen(name)))
            return start_domain;

        start_domain = start_domain->next;
    }

    return (qss_domain *) 0;
}

void remove_ip_in_domain(qss_domain_ip *q){
    qss_domain_ip *temp;
   
    if(q != NULL){
        temp = q;
        q = q->next;
        temp->prev = temp->next = NULL;
        temp->ip = NULL;
        free(temp);
    }
}

void remove_domain(qss_domain *start,qss_domain *q){
    qss_domain *temp;
            
    if((start != NULL) && (q != NULL)){
        temp = q;

        if( start == q ) {
            start = start->next;
        }

        else if(!q->next && q->prev){
            q->prev->next = NULL;
        }

        else if(q->next && q->prev){
            q->next->prev = q->prev;
            q->prev->next = q->next;
        }
    
        remove_ip_in_domain(temp->domain_ip);
        temp->domain_ip = NULL;
        temp->prev = temp->next = NULL;
        free(temp->d_name);
        free(temp);
    }
}

void remove_domain_list(qss_domain *q){
    qss_domain *temp;

    if(q != NULL){
        temp = q;
        q = q->next;
        remove_ip_in_domain(temp->domain_ip);
        temp->domain_ip = NULL;
        temp->prev = temp->next = NULL;
        free(temp->d_name);
        free(temp);
    }
}

qss_ip *new_ip(unsigned int ip){
    qss_ip *t_qss_ip;

    if((t_qss_ip = (qss_ip *) malloc(sizeof(struct qss_ip))) != NULL){
        t_qss_ip->ip = ip;
        t_qss_ip->black_hosts = 0;
        t_qss_ip->all_hosts = 0;
        t_qss_ip->white_hosts = 0;
        t_qss_ip->next = t_qss_ip->prev = NULL;
        return t_qss_ip;
    }

    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

qss_ip *add_ip_to_list(void **t_head,void **t_rear,void *qry,int t_type,int index){
	
    qss_ip **head = (qss_ip **) t_head;
    qss_ip **rear = (qss_ip **) t_rear;
    query *t_query = (query *) qry;
	
    qss_ip *t_ip_store = NULL;
	 
    if(head[index] == NULL){
	    head[index] = rear[index] = t_ip_store =  new_ip(t_query->srcip);
    } else {
	    if((t_ip_store = find_ip(head[index],t_query->srcip)) == 0){
	        t_ip_store = new_ip(t_query->srcip);
    	    rear[index]->next = t_ip_store;
    	    t_ip_store->prev = rear[index];
    	    rear[index] = t_ip_store;
    	}
    }

    if(t_type == 1)
	    t_ip_store->black_hosts++;
        
    if(t_type == 0)
       t_ip_store->white_hosts++;
    
    t_ip_store->all_hosts++;
    
    return t_ip_store;
}

qss_domain_ip *find_ip_in_domain(qss_domain_ip *q,unsigned int ip){
    
    qss_domain_ip *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip->ip == ip)
           return loop_ip;

        loop_ip = loop_ip->next;
    }
    return (qss_domain_ip *) 0;
}

qss_ip *find_ip(qss_ip *q,unsigned int ip){
    
    qss_ip *loop_ip = q;
    
    while(loop_ip){
        if(loop_ip->ip == ip){
           return loop_ip; 
        }

        loop_ip = loop_ip->next;
    }
    return (qss_ip *) 0;
}

void remove_ip(qss_ip **q,int size){
    int count;
    qss_ip *ip_store_temp,*ip_store_lookup;

    for(count = 0; count < size; count++){
        
        if(q[count] != NULL){
        
            ip_store_lookup = q[count];
            while(ip_store_lookup){
                ip_store_temp = ip_store_lookup;
                ip_store_lookup = ip_store_lookup->next;
                ip_store_temp->prev = ip_store_temp->next = NULL;
                free(ip_store_temp);
            }
        }   
    }
}

void remove_ip_single(qss_ip *q){
    qss_ip *temp;

    if(q != NULL){
        temp = q;
        q = q->next;
        temp->prev = temp->next = NULL;
        free(temp);
    }
}
