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
	int size = 1;
	st_host * list;
	query * q;
	moleWorld * st_mole = (moleWorld *)mole;

	q = st_mole->qlist_head;
	list = st_new_host(q->srcip);
	q = q->next;
	while (q != NULL) {
		if (st_add_query_to_list(list, q))
			size++;
		q = q->next;
	}

	st_host * h = list;
	int bad = 0;
	int normal = 0;
	while (h != NULL) {
		st_cal(h);
		//printf("%s\ttype: %x\n", inet_ntoa(h->ip), h->type);
		if (h->type == 0 || h->type == 0x10) normal++;
		else bad++;
		h = h->next;
	}

	printf("bad: %d\t normal: %d\n", bad, normal);
	/* report sth. */
}

void print_ip(domain_ip_store *dip){
        if(dip){
                    printf("\t\t%s (%i)\n",(char *)inet_ntoa(dip->ip->ip),dip->count);
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
    unsigned int count;
    storeMole->ipSpace = pow(2, (storeMole->parameters).subnet);
    ip_store *t_ip_store,*ip_store_head[storeMole->ipSpace],*ip_store_rear[storeMole->ipSpace];
    domain_store *d_head, *d_rear, *t_domain_store;
    domain_store *d_head_1, *d_rear_1;
    domain_store *d_head_2, *d_rear_2;
    kdomain *domain_list;
    query *t_query;
    
    int t_type;
    float half = (storeMole->parameters).analyze_interval/2.;
    unsigned int index;

    d_head = d_rear = NULL;
    d_head_1 = d_rear_1 = NULL;
    d_head_2 = d_rear_1 = NULL;
    
    for(count = 0; count < storeMole->ipSpace; count++)
        ip_store_head[count] = ip_store_rear[count] = NULL;
    
    time_t start = time(NULL);

    for(count = 0; count < num_packets; count++){
        //printf("%i - %i\n",count,num_packets);        
        t_type = -1;
        t_query = storeMole->qlist_head;
        
        index = t_query->srcip>>((storeMole->parameters).subnet);
        
        if(strcmp(t_query->dname,"DOBY.BIZ"))
            domain_list = search_domain(t_query->dname,storeMole->root_list,0);
            
        if(domain_list != 0)
            t_type = domain_list->suspicious;
       
        //printf("%s - %i\n",t_query->dname,t_type);
        if(ip_store_head[index] == NULL){
            ip_store_head[index] = ip_store_rear[index] = t_ip_store =  new_ip(t_query->srcip);
        } 
        else{
	        if((t_ip_store = find_ip(ip_store_head[index],t_query->srcip)) == 0){
                t_ip_store = new_ip(t_query->srcip);
                ip_store_rear[index]->next = t_ip_store;
                t_ip_store->prev = ip_store_rear[index];
                ip_store_rear[index] = t_ip_store;
            }
        }

        if(t_type == 1)
            t_ip_store->black_hosts++;
        
        if(t_type == 0)
            t_ip_store->white_hosts++;
        
        t_ip_store->all_hosts++;

        if((t_type == -1) || (t_type == 1)){
            time_t now = time(NULL);
                
            if((type == 1) || (((float)(now - t_query->time) < half))){
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
                
                if((type == 1) || (((float)(now - t_query->time) < half))){
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

                    if((type == 1) || (((float)(now - t_query->time) < half))){
                        d_rear_1 = d_rear;
                    }
                    else
                        d_rear_2 = d_rear;
                }
            }
        }
        
        storeMole->qlist_head = storeMole->qlist_head->next;
        query_remove(t_query);
    }
    printf("%i\n",(int)(time(NULL) - start));
    getchar();
    print_domain(d_head_1);
    print_domain(d_head_2);
    
    switch(type){
        case 1:
            first_method((void *) d_head_1,(void **) ip_store_head,(void *)storeMole);
            break;
        case 2:
            second_method((void *) d_head_1,(void *) d_head_2,(void *)storeMole);
            break;
    }
    printf("HELLO");
    remove_domain(d_head_1->next,1);
    remove_domain(d_head_1,0); 
    printf("XXXXXXXXX\n");
    remove_domain(d_head_1,1);
    if(type == 2) 
        remove_domain(d_head_2,1);
    //remove_ip(ip_store_head);
}

void second_method(void *domain_list_one,void *domain_list_two,void *mWorld){
    
    domain_store *d_head_1 = (domain_store *) domain_list_one;
    domain_store *d_head_2 = (domain_store *) domain_list_two;

    ip_store *ip_head_detected, *ip_rear_detected, *t_ip_detected, *t_ip;
    domain_ip_store *list_ip;
    moleWorld *groupMole = (moleWorld *) mWorld;
    char log_report[80];
    int a, b, c;
    float similarity = 0.0;

    a = b = c = 0;
    ip_head_detected = ip_rear_detected = NULL;

    domain_store *t_domain_1, *t_domain_2, *t_domain;

    for(t_domain_1 = d_head_1; t_domain_1 != NULL; ){
        
        if(t_domain_1->queried_with_different_ip < (groupMole->parameters).activity_drop){
            t_domain = t_domain_1->next;
            remove_domain(t_domain_1,0);
            t_domain_1 = t_domain;
        } else
            t_domain_1 = t_domain_1->next;
    }

    for(t_domain_2 = d_head_2; t_domain_2 != NULL; ){
        
        if(t_domain_2->queried_with_different_ip < (groupMole->parameters).activity_drop){
            t_domain = t_domain_2->next;
            remove_domain(t_domain_2,0);
            t_domain_2 = t_domain;
        } else
            t_domain_2 = t_domain_1->next;
    }

    t_domain_1 = d_head_1;

    while(t_domain_1){
        
        if((t_domain_2 = find_domain(d_head_2,t_domain_1->d_name))){
        
            a = t_domain_1->queried_with_different_ip;
            b = t_domain_2->queried_with_different_ip;
            list_ip = t_domain_1->domain_ip;
            
            while(list_ip){

                if(find_ip_in_domain(t_domain_2->domain_ip,list_ip->ip->ip)){
        
                    if(ip_head_detected == NULL){
                        ip_head_detected = ip_head_detected = new_ip(list_ip->ip->ip);

                    } else {
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
            
            if(similarity > (groupMole->parameters).activity_similarity){

                load_domain(t_domain_1->d_name,groupMole->re,groupMole->root_list,0);    
                snprintf(log_report,strlen(log_report),"Domain: (%s) added",t_domain_1->d_name);
                report(groupMole->log_fp,2,1,log_report);
                        
                t_ip = t_ip_detected;
                while(t_ip){
                    report(groupMole->log_fp,2,3,(char *)inet_ntoa(t_ip->ip));
                    t_ip = t_ip->next;
                }
            }

                
            remove_ip(t_ip_detected);    
            c = 0;
        }

        t_domain_1 = t_domain_1->next;
    }

    t_domain_1 = d_head_1;

    while(t_domain_1){

        t_domain_2 = d_head_2;

        if(t_domain_1 != t_domain_2){

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

                            } else {
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
                    if(similarity > (groupMole->parameters).activity_similarity){
                    
                        snprintf(log_report,strlen(log_report),"Domains: (%s) (%s) added",t_domain_1->d_name,t_domain_2->d_name);
                        load_domain(t_domain_1->d_name,groupMole->re,groupMole->root_list,0);    
                        load_domain(t_domain_2->d_name,groupMole->re,groupMole->root_list,0);
                        report(groupMole->log_fp,2,1,log_report);
                        
                        t_ip = t_ip_detected;
                        while(t_ip){
                            report(groupMole->log_fp,2,3,(char *) inet_ntoa(t_ip->ip));
                            t_ip = t_ip->next;
                        }
                    }   

                    remove_ip(t_ip_detected);
                }
                t_domain_2 = t_domain_2->next;
            }
        }

        t_domain_1 = t_domain_1->next;
    }
}

void first_method(void *domain,void **ip,void *mWorld){

    domain_store *d_head = (domain_store *) domain;
    ip_store **ip_store_head = (ip_store **) ip;
    moleWorld *blackMole = (moleWorld *) mWorld;

    float jaccard_index, index;
    int weight_infected, weight_all;
    int count = 0;
    int ipIndex = 0;
    int one = 0;
    ip_store *t_ip_store;
    char log_report[80];
    domain_store *t_domain_1, *t_domain_2, *t_dom;
    domain_ip_store *t_domain_ip,*t_ip_for_change;
    
    t_domain_1 = d_head;
    
    while(t_domain_1){
        
        if(t_dom){
            t_domain_1 = t_dom;
            t_dom = NULL;
        }

        if(t_domain_1->type == -1){
            
            jaccard_index = 0.0;
            index = 0.0;
            one = 0;
            weight_infected = weight_all = 0;
            t_domain_2 = d_head;

            while(t_domain_2){

                if(t_domain_2->type != -1){
                    one = 1;
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
        }

        if((index < (blackMole->parameters).o_white) && (index >= 0.0) && one){

            snprintf(log_report,strlen(log_report),"Domain: (%s) added",t_domain_1->d_name);
            report(blackMole->log_fp,1,1,log_report);

            load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,0);
                
            t_ip_for_change = t_domain_1->domain_ip;
            while(t_ip_for_change){
                ipIndex = t_ip_for_change->ip->ip % blackMole->ipSpace;
                t_ip_store = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_store->white_hosts += t_ip_for_change->count;
                t_ip_for_change = t_ip_for_change->next;
            }
                
            if(t_domain_1 == d_head)
                d_head = d_head->next;

            t_dom = t_domain_1->next;
            remove_domain(t_domain_1,0);
        }
            
        else if( index > (blackMole->parameters).o_black ){

            snprintf(log_report,strlen(log_report),"Domain: (%s) (%s) added",t_domain_1->d_name);
            report(blackMole->log_fp,1,1,log_report);
                
            load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,1);
                
            t_ip_for_change = t_domain_1->domain_ip;
            while(t_ip_for_change){
                ipIndex = t_ip_for_change->ip->ip >> blackMole->ipSpace;
                t_ip_store = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_store->black_hosts += t_ip_for_change->count;
                t_ip_for_change = t_ip_for_change->next;
            }
        }

        if(!t_dom)
            t_domain_1 = t_domain_1->next;
    }


    for(count = 0; count < pow(2,blackMole->ipSpace) && ip_store_head[count]; count++){
        t_ip_store = ip_store_head[count];

        while(t_ip_store){

            if((float)(t_ip_store->black_hosts/t_ip_store->all_hosts) >=  blackMole->parameters.black_ip_treshold)
                report(blackMole->log_fp,1,3,(char *)inet_ntoa(t_ip_store->ip));
                 
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
