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

#include "dnsmole.h"
#include "detection.h"

#define GA_LOG_DOMAIN "INSERT INTO ?s(date,name,type) VALUES(datetime('now'),'?s',?i)"
#define GA_LOG_DOMAIN_RELATION "INSERT INTO ?s(date,domain1,domain2) VALUES(datetime('now'),'?s','?s')"

void ga_initialize(void *tMole){

    moleWorld *gaMole = (moleWorld *) tMole;

    (gaMole->analyze_tv).tv_sec = (gaMole->parameters).a_analyze_interval;
    (gaMole->moleFunctions).filter = ga_filter;
    (gaMole->moleFunctions).analyze = ga_process;
}

int ga_filter(void *q_filter){

    query *query_filter = (query *) q_filter;

    if((query_filter->is_answer == 0) && (query_filter->q_type == 1)){
        return 1;
    }

    return 0;
}

void ga_process(unsigned  int n_pkt,void *tMole){
		 
    moleWorld *storeMole = (moleWorld *) tMole;
    unsigned int count,inner_count;
    storeMole->ipSpace = pow(2, (storeMole->parameters).subnet);
    
    qss_ip *t_ip_store,*ip_store_head[storeMole->ipSpace],*ip_store_rear[storeMole->ipSpace];
    qss_domain *d_head_1, *d_rear_1;
    qss_domain *d_head_2, *d_rear_2;
    query *t_query;
    kdomain *temp_domain;

    int t_type;
    
    unsigned int half_analyze;
    unsigned int index;
    
    time_t delta_time;
    
    d_head_1 = d_rear_1 = NULL;
    d_head_2 = d_rear_2 = NULL;

    for(count = 0; count < storeMole->ipSpace; count++)
        ip_store_head[count] = ip_store_rear[count] = NULL;

    if((storeMole->parameters).a_analyze_interval > storeMole->qlist_rear->time){
	    delta_time = storeMole->qlist_rear->time;
	    half_analyze = (storeMole->qlist_rear->time - storeMole->qlist_head->time) / 2;
    }
    else{
	    delta_time = storeMole->qlist_head->time + (storeMole->parameters).a_analyze_interval;
	    half_analyze = (storeMole->parameters).a_analyze_interval/2;
    }
    
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
       
        t_type = t_query->suspicious;
       
        t_ip_store = add_ip_to_list((void **) ip_store_head,(void **) ip_store_rear,(void *) t_query,t_type,index);
                
        if((t_type == -1) || (t_type == 1)){

            int difference = delta_time - t_query->time;

            if((difference < half_analyze)){
	            add_domain_to_list((void **)&d_head_2,(void **)&d_rear_2,(void *)t_query,(void *)t_ip_store,t_type);
            }
            
            else if(difference >= half_analyze)
		        add_domain_to_list((void **)&d_head_1,(void **)&d_rear_1,(void *)t_query,(void *)t_ip_store,t_type);    
        }
         
        storeMole->qlist_head = storeMole->qlist_head->next;
        query_remove(t_query);
        
        if(storeMole->qlist_head ? (storeMole->qlist_head->time > delta_time): 0){

	        ga_analyze((void *) d_head_1,(void *) d_head_2,(void *)storeMole);
	        d_head_1 = d_head_2 = d_rear_1 = d_rear_2 = NULL;
			
	        remove_ip(ip_store_head,storeMole->ipSpace);
			
	        for(inner_count = 0; inner_count < storeMole->ipSpace; inner_count++)
		        ip_store_head[inner_count] = ip_store_rear[inner_count] = NULL;
			
	        if(storeMole->qlist_rear->time <= (delta_time + (storeMole->parameters).a_analyze_interval)){
		        delta_time = storeMole->qlist_head ? storeMole->qlist_rear->time : time(NULL);
		        half_analyze = storeMole->qlist_head ? (storeMole->qlist_rear->time - storeMole->qlist_head->time) / 2 : 0;
	        }
	        else
		    delta_time += (storeMole->parameters).a_analyze_interval;
	    }	
		
	    else if(storeMole->qlist_head == NULL){
	        ga_analyze((void *) d_head_1,(void *) d_head_2,(void *)storeMole);
	        remove_ip(ip_store_head,storeMole->ipSpace);
	    }
    }
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

                    check_domain((void *)groupMole,t_domain_1->d_name,groupMole->root_list,1,0); 
                    useDB((void *)groupMole,GA_LOG_DOMAIN,"gaDomain",t_domain_1->d_name,1);

                } else if( similarity < (groupMole->parameters).activity_wl_similarity) {
                    
                    check_domain((void *)groupMole,t_domain_1->d_name,groupMole->root_list,0,0); 
                    useDB((void *)groupMole,GA_LOG_DOMAIN,"gaDomain",t_domain_1->d_name,0);
                
                    t_domain = t_domain_1->next;

                    if(d_head_1 == t_domain_1)
                        d_head_1 = d_head_1->next;
                    
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
                            
                            check_domain((void *)groupMole,t_domain_1->d_name,groupMole->root_list,1,0); 
                            check_domain((void *)groupMole,t_domain_2->d_name,groupMole->root_list,1,0); 
                            useDB((void *)groupMole,GA_LOG_DOMAIN_RELATION,"gaDomainRelation",t_domain_1->d_name,t_domain_2->d_name);
                            
                            
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
