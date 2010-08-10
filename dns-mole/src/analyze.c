/* analyze.c
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

void _learn(int fd,short event,void *arg){
    
    moleWorld *myMole= (moleWorld *) arg;

    switch(myMole->type){
        case 1:
            break;
        case 2:
            break;
    }
    
    event_add(&myMole->analyze_ev,&myMole->analyze_tv);
}

void _analyzer(int fd,short event,void *arg){

    moleWorld *analyzeMole = (moleWorld *) arg;
    int num_packets = analyzeMole->count;

    analyzeMole->count = 0;
    switch(analyzeMole->type){
        case 1:
            populate_store_structure(num_packets,(void *) analyzeMole,1);
	    break;
        case 2:
            populate_store_structure(num_packets,(void *) analyzeMole,2);
            break;
        case 3:
	    statistics_method(num_packets,(void *) analyzeMole);
            break;
    }
    
    event_add(&analyzeMole->analyze_ev,&analyzeMole->analyze_tv);
                    
}                    

void statistics_method(int num, void *mole) {
	int i;
	st_host * list;
	query * q;
	moleWorld * st_mole = (moleWorld *)mole;

	q = st_mole->qlist_head;
	list = st_new_host(q->srcip);
	q = q->next;
	while (q != NULL) {
		st_add_query_to_list(list, q);
		q = q->next;
	}
	
	st_host * h = list;
	while (h != NULL) {
		st_cal(h);
		h = h->next;
	}

	/* report sth. */
}

void p_ip(ip_store *q){
    if(q){
        printf("%s (%i)\n",inet_ntoa(q->ip),q->all_hosts);
        p_ip(q->next);
    }
}

void print_ip(domain_ip_store *dip){
    if(dip){
        printf("\t\t%s (%i)\n",inet_ntoa(dip->ip->ip),dip->count);
        print_ip(dip->next);
    }
}

void print_domain(domain_store *d){
    if(d){
        printf("domain: %s\n",d->d_name);
        print_ip(d->domain_ip);
        print_domain(d->next);
    }
}
void populate_store_structure(int num_packets,void *black,int type){

    moleWorld *storeMole = (moleWorld *) black;
    int count;
    
    ip_store *t_ip_store,*ip_store_head,*ip_store_rear;
    domain_store *d_head, *d_rear, *t_domain_store;
    domain_store *d_head_1, *d_rear_1;
    domain_store *d_head_2, *d_rear_2;
    kdomain *domain_list;
    query *t_query;
    
    int t_type;

    d_head = d_rear = NULL;
    d_head_1 = d_rear_1 = NULL;
    d_head_2 = d_rear_1 = NULL;
    ip_store_head = ip_store_rear = NULL;
    

    for(count = 0; count < num_packets; count++){
        t_type = -1;
        t_query = storeMole->qlist_head;
        
        domain_list = search_domain(t_query->dname,storeMole->root_list);

        if(domain_list)
            t_type = domain_list->suspicious;
        
        if(ip_store_head == NULL){
            ip_store_head = ip_store_rear = new_ip(t_query->srcip);
            t_ip_store = ip_store_rear;
        }
            
        else{
	        if((t_ip_store = find_ip(ip_store_head,t_query->srcip)) == 0){
                t_ip_store = new_ip(t_query->srcip);
                ip_store_rear->next = t_ip_store;
                t_ip_store->prev = ip_store_rear;
                ip_store_rear = t_ip_store;
            }
        }  
        if(t_type == 1)
            t_ip_store->black_hosts++;
        
        if(t_type == 0)
            t_ip_store->white_hosts++;
        
        t_ip_store->all_hosts++;

        if(t_type == -1 || t_type == 1){
            
            time_t now = time(NULL);
            
            if((type == 1) || ((now - t_query->time) < (now-t_query->time)/2)){
                d_head = d_head_1;
                d_rear = d_rear_1;
            }
            else{
                d_head = d_head_2;
                d_rear = d_rear_2;
            }

            if(d_head == NULL){
                d_head = d_rear = new_domain(t_query->dname,t_type);
                add_ip_to_domain(d_rear,(void *)t_ip_store); 
            
                if((type == 1) || ((now - t_query->time) < (now-t_query->time)/2)){
                    d_head_1 = d_head;
                    d_rear_1 = d_rear;
                }
                else{
                    d_head_2 = d_head;
                    d_rear_2 = d_rear;
                }
            }
        
            else{
                if((t_domain_store = find_domain(d_head,t_query->dname))){
                    add_ip_to_domain(t_domain_store,(void *)t_ip_store);
                }
                else{
                    t_domain_store = new_domain(t_query->dname,t_type);
                    add_ip_to_domain(t_domain_store,(void *)t_ip_store);
                    t_domain_store->prev = d_rear;
                    d_rear->next = t_domain_store;
                    d_rear = d_rear->next;

                    if((type == 1) || ((now - t_query->time) < (now-t_query->time)/2)){
                        d_rear_1 = d_rear;
                    }
                    else{
                        d_rear_2 = d_rear;
                    }
                }
            }
        }
        storeMole->qlist_head = storeMole->qlist_head->next;
        query_remove(t_query);
    }
   
    print_domain(d_head_1);
    printf("\t\tDONE \n");
    p_ip(ip_store_head);
    printf("\t\t....\n");
    switch(type){
        case 1:
            first_method((void *) d_head_1,(void *) ip_store_head,(void *)storeMole);
            break;
        case 2:
            //second_method((void *) d_head_1,(void *) d_head_2,(void *) ip_store_head,(void *)storeMole);
            break;
    }
    printf("XXX\n");
    remove_domain(d_head_1,1);
    remove_domain(d_head_2,1);
    remove_ip(ip_store_head);
}

void second_method(void *domain_list_one,void *domain_list_two,void *ip,void *mWorld){
    
    domain_store *d_head_1 = (domain_store *) domain_list_one;
    domain_store *d_head_2 = (domain_store *) domain_list_two;
    ip_store *ip_store_head = (ip_store *) ip;
    ip_store *ip_head_detected, *ip_rear_detected, *t_ip_detected;
    domain_ip_store *list_ip;
    moleWorld *groupMole = (moleWorld *) mWorld;
    int a, b, c;
    float similarity = 0.0;

    a = b = c = 0;
    ip_head_detected = ip_rear_detected = NULL;

    domain_store *t_domain_1, *t_domain_2;

    t_domain_1 = d_head_1;

    while(t_domain_1){
        t_domain_2 = find_domain(d_head_2,t_domain_1->d_name);
    
        if(t_domain_1->queried_with_different_ip < groupMole->parameters.activity_drop){
            remove_domain(t_domain_1,0);
        }
        else if(t_domain_2->queried_with_different_ip < groupMole->parameters.activity_drop){
            remove_domain(t_domain_2,0);
        }

        else{
            a = t_domain_1->queried_with_different_ip;
            b = t_domain_2->queried_with_different_ip;
            list_ip = t_domain_1->domain_ip;
            
            while(list_ip){
                if(find_ip_in_domain(t_domain_2->domain_ip,list_ip->ip->ip)){
                    if(ip_head_detected == NULL){
                        ip_head_detected = ip_head_detected = new_ip(list_ip->ip->ip);
                    }
            
                    else{
                        t_ip_detected = new_ip(list_ip->ip->ip);
                        ip_rear_detected->next = t_ip_detected;
                        t_ip_detected->prev = ip_rear_detected;
                        ip_rear_detected = t_ip_detected;
                    }

                    c++;
                }

                list_ip = list_ip->next;
            }

            similarity = 0.5*((float)c/a + (float)c/b);
            
            if(similarity > groupMole->parameters.activity_similarity){
                
                /* report sth. */
            }


            remove_ip(ip_head_detected);    
            c = 0;
        }

        t_domain_1 = t_domain_1->next;
    }

    t_domain_1 = d_head_1;

    while(t_domain_1){
        t_domain_2 = d_head_2;

        if(t_domain_1 != t_domain_2){

            if(t_domain_2->queried_with_different_ip < groupMole->parameters.activity_drop)
                remove_domain(t_domain_2,0);
        

            while(t_domain_2){
                c = 0;
                if(abs(t_domain_1->queried_with_different_ip - t_domain_2->queried_with_different_ip) 
                    < 0.1*t_domain_1->queried_with_different_ip){

                    a = t_domain_1->queried_with_different_ip;        
                    b = t_domain_1->queried_with_different_ip;
                    list_ip = t_domain_1->domain_ip;

                    while(list_ip){
                        if(find_ip_in_domain(t_domain_2->domain_ip,list_ip->ip->ip)){
                            if(ip_head_detected == NULL){
                                ip_head_detected = ip_head_detected = new_ip(list_ip->ip->ip); 
                            }
                            else{
                                t_ip_detected = new_ip(list_ip->ip->ip);
                                ip_rear_detected->next = t_ip_detected;
                                t_ip_detected->prev = ip_rear_detected;
                                ip_rear_detected = t_ip_detected;
                            }
                        
                            c++;
                        }
                
                        list_ip = list_ip->next;
                    }

                    similarity = 0.5*((float)c/a + (float)c/b);
                    if(similarity > groupMole->parameters.activity_similarity){

                        /* report sth. */

                    }   

                    remove_ip(ip_head_detected);
                }
                t_domain_2 = t_domain_2->next;
            }
        }
        t_domain_1 = t_domain_1->next;
    }
}

void first_method(void *domain,void *ip,void *mWorld){

    domain_store *d_head = (domain_store *) domain;
    ip_store *ip_store_head = (ip_store *) ip;
    moleWorld *blackMole = (moleWorld *) mWorld;

    float jaccard_index, index;
    int weight_infected, weight_all;
    ip_store *t_ip_store;
    domain_store *t_domain_1, *t_domain_2;
    domain_ip_store *t_domain_ip,*t_ip_for_change;
    
    t_domain_1 = d_head;
    while(t_domain_1){

        if(t_domain_1->type == -1){
            jaccard_index = index = 0.0;
            weight_infected = weight_all = 0;
            t_domain_2 = d_head;

            while(t_domain_2){

                if(t_domain_2->type != -1){
                    jaccard_index += calculate_jaccard_index(t_domain_1,t_domain_2);
                }

            t_domain_2 = t_domain_2->next; 
            }

            t_domain_ip = t_domain_1->domain_ip;
                
            while(t_domain_ip){

                if((float)(t_domain_ip->ip->black_hosts / t_domain_ip->ip->all_hosts) > blackMole->parameters.black_ip_treshold )
                    weight_infected++;

                weight_all++;
                t_domain_ip = t_domain_ip->next;
            }

            index = jaccard_index * (weight_infected/weight_all);
            printf("\t\t index: %f\n",index);            
            if( index < blackMole->parameters.o_white ){

                /* report sth. */
                
                load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,0);
                
                t_ip_for_change = t_domain_1->domain_ip;
                while(t_ip_for_change){
                    printf("(%s) %s\n",t_domain_1->d_name,inet_ntoa(t_ip_for_change->ip->ip));
                    t_ip_store = find_ip(ip_store_head,t_ip_for_change->ip->ip);
                    printf("%s\n",inet_ntoa(t_ip_store->ip));
                    t_ip_store->white_hosts += t_ip_for_change->count;
                    t_ip_for_change = t_ip_for_change->next;
                }
                
                if(t_domain_1 == d_head && d_head->next)
                    d_head = d_head->next;

                remove_domain(t_domain_1,0);
            }
            
            else if( index > blackMole->parameters.o_black ){

                /* report sth. */

                load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,1);
                
                t_ip_for_change = t_domain_1->domain_ip;
                while(t_ip_for_change){
                    t_ip_store = find_ip(ip_store_head,t_ip_for_change->ip->ip);
                    t_ip_store->black_hosts += t_ip_for_change->count;
                    t_ip_for_change = t_ip_for_change->next;
                }
            }
        }

        t_domain_1 = t_domain_1->next;
    }

    t_ip_store = ip_store_head;
    
    if(t_ip_store){

        while(t_ip_store){

            if((float)(t_ip_store->black_hosts/t_ip_store->all_hosts) >=  blackMole->parameters.black_ip_treshold){
        
                /* report sth */

            }
            t_ip_store = t_ip_store->next;
        }
    }
}

float calculate_jaccard_index(void *unknown,void *black){

    domain_store *unknown_domain = (domain_store *) unknown;
    domain_store *black_domain = (domain_store *) black;
    domain_ip_store *black_domain_ip = black_domain->domain_ip;
    domain_ip_store *t_domain_ip_store;
    int numerator = 0, denominator = 0, dh =0;

    while(black_domain_ip){
        if(t_domain_ip_store = find_ip_in_domain(unknown_domain->domain_ip,black_domain_ip->ip->ip))        
            numerator += t_domain_ip_store->count/t_domain_ip_store->ip->all_hosts;

        black_domain_ip = black_domain_ip->next;
    }

    denominator = black_domain->queried_overall + unknown_domain->queried_overall;

    return (numerator/denominator);
}
