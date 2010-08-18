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
	int net_size = 1;
	st_host * list;
	query * q;
	moleWorld * st_mole = (moleWorld *)mole;

	q = st_mole->qlist_head;
	list = st_new_host(q->srcip, q);
	q = q->next;
	int packet_count = 0;
	while (q != NULL) {
		if (st_add_query_to_list(list, q, st_mole))
			net_size++;
		packet_count++;
		q = q->next;
	}

	int select_num = net_size * RATE;
	st_host ** h = st_frequent_host_selection(list, select_num);

	int bad = 0;
	int normal = 0;
	char msg[512];
	int i;
	report(st_mole->log_fp,NULL,NULL,0,3, 4,"[Using statistics]\n");
	for (i = 0; i < select_num; i++) {
        printf("%i\n",i);
		st_cal(h[i], st_mole);
		if (h[i]->abnormal_type == 0) normal++;
		else {
			sprintf(msg, "\t%s\t%s\n\t\ttotal: %d\tmx: %d\tptr: %d\n\t\ttime: %s\t\tt_total: %f\tt_balance: %f\n" 
				"\t\tt_ptr: %f\tt_ptr_rate: %f\n\t\tt_mx: %f\tt_mx_rate: %f\n\t\tanormal type: %x\n", 
				inet_ntoa(*(struct in_addr *)&h[i]->ip),
				(h[i]->kind == 1)?"Server":"Client",
				h[i]->total, h[i]->mx_total, h[i]->ptr_total,
				ctime((const time_t *)&h[i]->start_time),
				h[i]->t_total, h[i]->t_balance,
				h[i]->t_ptr, h[i]->t_ptr_rate,
				h[i]->t_mx, h[i]->t_mx_rate,
				h[i]->abnormal_type
				);
			report(st_mole->log_fp,NULL,NULL,0,3, 4, msg);
			//printf("%s", msg);
			bad++;
		}
	}

	sprintf(msg, "[%d] packets captured\n[%d] hosts selected\n[%d] total hosts\n[%d] abnormal\n", packet_count, select_num, net_size, bad);
	report(st_mole->log_fp,NULL,NULL,0, 3, 4, msg);
	printf("%s", msg);
}

int is_domain_name_valid(const char *domain){
    int domain_size = strlen(domain);
    int lookup;
    for(lookup = 0; lookup < domain_size; lookup++){
        if(isalpha(domain[lookup]) || isdigit(domain[lookup]) || (domain[lookup] == '.') || (domain[lookup] == '-') || (domain[lookup] == '_')){
            if(((domain[lookup] == '.' && domain[lookup+1] == '-')) || (domain[lookup] == '.' && domain[lookup+1] == '.') 
                    || (domain[lookup] == '.' && domain[lookup] == '\0')){
                return 0;
            }
        } else {
            return 0;
        }
    }
    return 1;
}

void populate_store_structure(int num_packets,void *black,int type){

    
    moleWorld *storeMole = (moleWorld *) black;
    unsigned int count;
    storeMole->ipSpace = pow(2, (storeMole->parameters).subnet);
    
    ip_store *t_ip_store,*ip_store_head[storeMole->ipSpace],*ip_store_rear[storeMole->ipSpace];
    domain_store *d_head, *d_rear, *t_domain_store;
    domain_store *d_head_1, *d_rear_1;
    domain_store *d_head_2, *d_rear_2;
    query *t_query,*t_query_temp;
    kdomain *temp_domain;

    int t_type;
    int do_first = 1;
    
    unsigned int half_analyze;
    unsigned int index;
    int not_valid_names = 0;
    time_t store_first_q_time;
    time_t s_analyse = time(NULL);

    d_head = d_rear = NULL;
    d_head_1 = d_rear_1 = NULL;
    d_head_2 = d_rear_2 = NULL;

    for(count = 0; count < storeMole->ipSpace; count++)
        ip_store_head[count] = ip_store_rear[count] = NULL;

    if((storeMole->parameters).pcap_interval != 0){
        store_first_q_time = storeMole->qlist_head->time + (storeMole->parameters).pcap_interval;
        half_analyze = (storeMole->parameters).pcap_interval / 2;
    } else {
        store_first_q_time = (storeMole->qlist_head ? storeMole->qlist_head->time + (storeMole->analyze_tv).tv_sec : time(NULL));
        half_analyze = (storeMole->analyze_tv).tv_sec / 2;
    }
    
    
    t_query = storeMole->qlist_head; 
    fprintf(stdout,"[ Starting Analysis (num_packets: %i)]\n",num_packets);

    for(count = 0; count < num_packets; count ++){
        if(!is_domain_name_valid(t_query->dname)){
            t_query_temp = t_query->next;
            query_remove(t_query);
            t_query = t_query_temp;
            not_valid_names++;
        } else {
            temp_domain = search_domain(t_query->dname,storeMole->root_list,0);
            t_query->suspicious = -1;   
            
            if(temp_domain)
                t_query->suspicious = temp_domain->suspicious;
        
            t_query = t_query->next;
        }
    }
    
    for(count = 0; count < (num_packets - not_valid_names); count++){
        t_type = -1;
        t_query = storeMole->qlist_head;
        index = (t_query->srcip)&((signed int)1>>((storeMole->parameters).subnet));
        
        t_type = t_query->suspicious;
       
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

            int difference = store_first_q_time - t_query->time;

            if((difference < half_analyze)){
                do_first = 1;
            }
            else if(difference >= half_analyze){
                do_first = 0;
            }

            if((type == 1) || do_first){
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
                
                if((type == 1) || do_first){
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

                    if((type == 1) || do_first){
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
    fprintf(stdout,"[ End creating structures (%i)]\n",time(NULL) - s_analyse);

    switch(type){
        case 1:
            first_method((void *) d_head_1,(void **) ip_store_head,(void *)storeMole);
            break;
        case 2:
            second_method((void *) d_head_1,(void *) d_head_2,(void *)storeMole);
            break;
    }

    fprintf(stdout,"[ End Analysis (%i)]\n",time(NULL) - s_analyse);
    remove_ip(ip_store_head,storeMole->ipSpace);
}

void second_method(void *domain_list_one,void *domain_list_two,void *mWorld){
    
    domain_store *d_head_1 = (domain_store *) domain_list_one;
    domain_store *d_head_2 = (domain_store *) domain_list_two;

    domain_ip_store *list_ip;
    moleWorld *groupMole = (moleWorld *) mWorld;
    int a, b, c;
    float similarity = 0.0;

    a = b = c = 0;

    domain_store *t_domain_1, *t_domain_2, *t_domain = NULL;

    t_domain_1 = d_head_1;

    while(t_domain_1){
        if(t_domain_1->queried_with_different_ip < (groupMole->parameters).activity_drop){
            t_domain = t_domain_1->next;

            if(d_head_1 == t_domain_1)
                d_head_1 = d_head_1->next;

            remove_domain(d_head_1,t_domain_1);
            t_domain_1 = t_domain;
        
        } else

            t_domain_1 = t_domain_1->next;
    }
    
    t_domain_2 = d_head_2;
    
    while(t_domain_2){
        
        if(t_domain_2->queried_with_different_ip < (groupMole->parameters).activity_drop){
            t_domain = t_domain_2->next;
            
            if(d_head_2 == t_domain_2)
                d_head_2 = d_head_2->next;

            remove_domain(d_head_2,t_domain_2);
            t_domain_2 = t_domain;

        } else
            t_domain_2 = t_domain_2->next;
    }

    t_domain_1 = d_head_1;
    t_domain = NULL;

    
    while(t_domain_1){

        if(t_domain){
            t_domain_1 = t_domain; t_domain = NULL;
        }

        if((t_domain_2 = find_domain(d_head_2,t_domain_1->d_name))){
            a = t_domain_1->queried_with_different_ip;
            b = t_domain_2->queried_with_different_ip;
            
            list_ip = t_domain_1->domain_ip;
            
            while(list_ip){

                if(find_ip_in_domain(t_domain_2->domain_ip,list_ip->ip->ip))
                    c++;

                list_ip = list_ip->next;
            }
                
            
            if((a != 0) && (b != 0)){
                similarity = 0.5*((float)c/a + (float)c/b);
            
                if(similarity > (groupMole->parameters).activity_bl_similarity){

                    load_domain(t_domain_1->d_name,groupMole->root_list,1);    
                    report(groupMole->log_fp,t_domain_1->d_name,NULL,0,2,1,NULL);

                } else if( similarity < (groupMole->parameters).activity_wl_similarity) {
                
                    t_domain = t_domain_1->next;

                    if(d_head_1 == t_domain_1)
                        d_head_1 = d_head_1->next;

                    load_domain(t_domain_1->d_name,groupMole->root_list,0);
                    report(groupMole->log_fp,t_domain_1->d_name,NULL,0,2,2,NULL);
                    remove_domain(d_head_1,t_domain_1);

                }

                c = 0;
            }
        }

        if(!t_domain)
            t_domain_1 = t_domain_1->next;
    }

    t_domain_1 = d_head_1;

    while(t_domain_1){

        t_domain_2 = d_head_2;

        while(t_domain_2){

            if(memcmp(t_domain_1->d_name,t_domain_2->d_name,strlen(t_domain_2->d_name))){
                
                c = 0;
        
                if(abs(t_domain_1->queried_with_different_ip - t_domain_2->queried_with_different_ip) < 0.1*t_domain_1->queried_with_different_ip){

                    a = t_domain_1->queried_with_different_ip;        
                    b = t_domain_2->queried_with_different_ip;
                    list_ip = t_domain_1->domain_ip;

                    while(list_ip){

                        if(find_ip_in_domain(t_domain_2->domain_ip,list_ip->ip->ip))
                            c++;
                
                        list_ip = list_ip->next;
                    }

                    if(c != 0){
                        
                        similarity = 0.5*((float)c/a + (float)c/b);
                    
                        if(similarity > (groupMole->parameters).activity_bl_similarity){
                                 
                            load_domain(t_domain_1->d_name,groupMole->root_list,1);    
                            load_domain(t_domain_2->d_name,groupMole->root_list,1);
                            report(groupMole->log_fp,t_domain_1->d_name,t_domain_2->d_name,0,2,1,NULL); 
                            
                        }   

                    } 

                }
            
            }

            t_domain_2 = t_domain_2->next;
        }

        t_domain_1 = t_domain_1->next;
    }

    remove_domain_list(d_head_1);
    remove_domain_list(d_head_2);
}

void first_method(void *domain,void **ip,void *mWorld){

    domain_store *d_head = (domain_store *) domain;
    ip_store **ip_store_head = (ip_store **) ip;
    moleWorld *blackMole = (moleWorld *) mWorld;

    float jaccard_index, index = 0.0;
    int weight_infected, weight_all;
    int count = 0;
    int ipIndex = 0;
    int one = 0;
    ip_store *t_ip_store;
    domain_store *t_domain_1, *t_domain_2, *t_dom = NULL;
    domain_ip_store *t_domain_ip,*t_ip_for_change;
    
    t_domain_1 = d_head;
    
    while(t_domain_1){
        if(t_dom){
            t_domain_1 = t_dom; t_dom = NULL;
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

            report(blackMole->log_fp,t_domain_1->d_name,NULL,0,1,2,NULL);

            load_domain(t_domain_1->d_name,blackMole->root_list,0);
                
            t_ip_for_change = t_domain_1->domain_ip;
            while(t_ip_for_change){
                ipIndex = t_ip_for_change->ip->ip & ((signed int) 1 >> (blackMole->parameters).subnet);
                t_ip_store = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_store->white_hosts += t_ip_for_change->count;
                t_ip_for_change = t_ip_for_change->next;
            }

            t_dom = t_domain_1->next;

            if(d_head == t_domain_1)
                d_head = d_head->next;
            
            remove_domain(d_head,t_domain_1);
        }
            
        else if( index > (blackMole->parameters).o_black ){

            report(blackMole->log_fp,t_domain_1->d_name,NULL,0,1,1,NULL);
                
            load_domain(t_domain_1->d_name,blackMole->root_list,1);
                
            t_ip_for_change = t_domain_1->domain_ip;
            while(t_ip_for_change){
                ipIndex = t_ip_for_change->ip->ip & ((signed int)1 >> (blackMole->parameters).subnet);
                t_ip_store = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_store->black_hosts += t_ip_for_change->count;
                t_ip_for_change = t_ip_for_change->next;
            }
        }

        if(!t_dom)
            t_domain_1 = t_domain_1->next;
    }


    for(count = 0; (count < blackMole->ipSpace) && (ip_store_head[count] != NULL); count++){
        t_ip_store = ip_store_head[count];

        if(t_ip_store){
            while(t_ip_store){

                if(((float)t_ip_store->black_hosts/(float)t_ip_store->all_hosts) >=  (blackMole->parameters).black_ip_treshold)
                    report(blackMole->log_fp,NULL,NULL,t_ip_store->ip,1,3,NULL);
                 
                t_ip_store = t_ip_store->next;
            }
        }
    }

    remove_domain_list(d_head);
}

float calculate_jaccard_index(void *unknown,void *black){

    domain_store *unknown_domain = (domain_store *) unknown;
    domain_store *black_domain = (domain_store *) black;
    domain_ip_store *black_domain_ip = black_domain->domain_ip;
    domain_ip_store *t_domain_ip_store;
    int numerator = 0, denominator = 0;

    while(black_domain_ip){
        if((t_domain_ip_store = find_ip_in_domain(unknown_domain->domain_ip,black_domain_ip->ip->ip)))        
            numerator += t_domain_ip_store->count/t_domain_ip_store->ip->all_hosts;

        black_domain_ip = black_domain_ip->next;
    }

    denominator = black_domain->queried_overall + unknown_domain->queried_overall;

    return (numerator/denominator);
}
