/* ga-detection.c
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

#include "detection.h"

void ga_initialize(moleWorld corMole){

    corMole.moleFunctions.filter = ga_filter;
    corMole.moleFunctions.analyze = ga_process;
    //corMole.moleFunctions.log = ga_log;
}

int ga_filter(void *q_filter){

    query *query_filter = (query *) q_filter;

    if((query_filter->is_answer == 1) && (query_filter->q_type != 1)){
        return 1;
    }

    return 0;
}

void ga_process(unsigned  int n_pkt,void *tMole){
		 
    moleWorld *storeMole = (moleWorld *) tMole;
    unsigned int count;
    storeMole->ipSpace = pow(2, (storeMole->parameters).subnet);
    
    qss_ip *t_ip_store,*ip_store_head[storeMole->ipSpace],*ip_store_rear[storeMole->ipSpace];
    qss_domain *d_head, *d_rear, *t_domain_store;
    qss_domain *d_head_1, *d_rear_1;
    qss_domain *d_head_2, *d_rear_2;
    query *t_query,*t_query_temp;
    //kdomain *temp_domain;

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
    } 
    else {
        store_first_q_time = (storeMole->qlist_head ? storeMole->qlist_head->time + (storeMole->analyze_tv).tv_sec : time(NULL));
        half_analyze = (storeMole->analyze_tv).tv_sec / 2;
    }
    
    
    t_query = storeMole->qlist_head; 

    for(count = 0; count < n_pkt; count ++){
      //  if(!is_domain_name_valid(t_query->dname)){
            t_query_temp = t_query->next;
            query_remove(t_query);
            t_query = t_query_temp;
            not_valid_names++;
        /*} else {
            temp_domain = search_domain(t_query->dname,storeMole->root_list,0);
            t_query->suspicious = -1;   
            
            if(temp_domain)
                t_query->suspicious = temp_domain->suspicious;
        
            t_query = t_query->next;
        }*/
    }
    
    for(count = 0; count < (n_pkt - not_valid_names); count++){
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

            if(do_first){
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
                
                if(do_first){
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

                    if(do_first){
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
    
   ga_analyze((void *) d_head_1,(void *) d_head_2,(void *)storeMole);
   remove_ip(ip_store_head,storeMole->ipSpace);
}

void ga_analyze(void *domain_list_one,void *domain_list_two,void *mWorld){
    
    qss_domain *d_head_1 = (qss_domain *) domain_list_one;
    qss_domain *d_head_2 = (qss_domain *) domain_list_two;

    qss_domain_ip *list_ip;
    moleWorld *groupMole = (moleWorld *) mWorld;
    int a, b, c;
    float similarity = 0.0;

    a = b = c = 0;

    qss_domain *t_domain_1, *t_domain_2, *t_domain = NULL;

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
