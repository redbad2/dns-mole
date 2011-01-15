/* cor-detection.c
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
 
void cor_initialize(void *tMole){
    

    moleWorld *corMole = (moleWorld *) tMole;

    (corMole->analyze_tv).tv_sec = (corMole->parameters).a_analyze_interval;
    (corMole->moleFunctions).filter = cor_filter;
    (corMole->moleFunctions).analyze = cor_process;
}

int cor_filter(void *q_filter){

    query *query_filter = (query *) q_filter;

    if((query_filter->is_answer == 0) && (query_filter->q_type == 1)){
        return 1;
    }

    return 0;
}

void cor_process(unsigned int n_pkt,void *tMole){
	
    moleWorld *storeMole = (moleWorld *) tMole;
    unsigned int count;
    storeMole->ipSpace = pow(2, (storeMole->parameters).subnet);
    
    qss_ip *t_ip_store,*ip_store_head[storeMole->ipSpace],*ip_store_rear[storeMole->ipSpace];
    qss_domain *d_head, *d_rear, *t_domain_store;
    query *t_query;
    kdomain *temp_domain;

    int t_type;
    unsigned int index;

    d_head = d_rear = NULL;
    
    for(count = 0; count < storeMole->ipSpace; count++)
        ip_store_head[count] = ip_store_rear[count] = NULL;
    
    t_query = storeMole->qlist_head; 
    
    for(count = 0; count < n_pkt; count ++){
		
        temp_domain = search_domain(t_query->dname,storeMole->root_list,0);
        t_query->suspicious = -1;   
            
        if(temp_domain)
            t_query->suspicious = temp_domain->suspicious;
        
        t_query = t_query->next;
    }
    
    for(count = 0; count < n_pkt; count++){
        
        t_type = -1;
        t_query = storeMole->qlist_head;
        index = (t_query->srcip)&((signed int)1>>((storeMole->parameters).subnet));
        
        printf("%s,%s\n",t_query->dname,ctime(&t_query->time));
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

            if(d_head == NULL){
                d_head = d_rear = new_domain(t_query->dname,t_type);
                add_ip_to_domain(d_rear,(void *)t_ip_store);   
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
                }
            }
        }
        
        storeMole->qlist_head = storeMole->qlist_head->next;
        query_remove(t_query);
    }
    
    cor_analyze((void *) d_head,(void **) ip_store_head,(void *)storeMole);
    remove_ip(ip_store_head,storeMole->ipSpace);
}
void cor_analyze(void *domain,void **ip,void *mWorld){

    qss_domain *d_head = (qss_domain *) domain;
    qss_ip **ip_store_head = (qss_ip **) ip;
    moleWorld *blackMole = (moleWorld *) mWorld;

    float jaccard_index, index = 0.0;
    int weight_infected, weight_all;
    int count = 0;
    int ipIndex = 0;
    int one = 0;
    qss_ip *t_ip_sort;
    qss_domain *t_domain_1, *t_domain_2, *t_dom = NULL;
    qss_domain_ip *t_domain_ip,*t_ip_for_change;
    
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
                if((float)(t_domain_ip->ip->black_hosts / t_domain_ip->ip->all_hosts) > blackMole->parameters.black_ip_treshold)
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
                t_ip_sort = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_sort->white_hosts += t_ip_for_change->count;
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
                t_ip_sort = find_ip(ip_store_head[ipIndex],t_ip_for_change->ip->ip);
                t_ip_sort->black_hosts += t_ip_for_change->count;
                t_ip_for_change = t_ip_for_change->next;
            }
        }

        if(!t_dom)
            t_domain_1 = t_domain_1->next;
    }


    for(count = 0; (count < blackMole->ipSpace) && (ip_store_head[count] != NULL); count++){
        t_ip_sort = ip_store_head[count];

        if(t_ip_sort){
            while(t_ip_sort){

                if(((float)t_ip_sort->black_hosts/(float)t_ip_sort->all_hosts) >=  (blackMole->parameters).black_ip_treshold)
                    report(blackMole->log_fp,NULL,NULL,t_ip_sort->ip,1,3,NULL);
                 
                t_ip_sort = t_ip_sort->next;
            }
        }
    }

    remove_domain_list(d_head);
}

float calculate_jaccard_index(void *unknown,void *black){

    qss_domain *unknown_domain = (qss_domain *) unknown;
    qss_domain *black_domain = (qss_domain *) black;
    qss_domain_ip *black_domain_ip = black_domain->domain_ip;
    qss_domain_ip *t_domain_ip_store;
    int numerator = 0, denominator = 0;

    while(black_domain_ip){
        if((t_domain_ip_store = find_ip_in_domain(unknown_domain->domain_ip,black_domain_ip->ip->ip)))        
            numerator += t_domain_ip_store->count/t_domain_ip_store->ip->all_hosts;

        black_domain_ip = black_domain_ip->next;
    }

    denominator = black_domain->queried_overall + unknown_domain->queried_overall;

    return (numerator/denominator);
}

