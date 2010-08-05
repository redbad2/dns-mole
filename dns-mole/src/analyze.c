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
            blacklist_method(num_packets,(void *) analyzeMole);
            break;
    }
                   
    event_add(&analyzeMole->analyze_ev,&analyzeMole->analyze_tv);
                    
}                    
                    
void blacklist_method(int num,void *black){

    moleWorld *blackMole = (moleWorld *) black;
    
    int cnt;
    query *t_query;
    kdomain *list_domain;
    ip_list *t_ip,*ip_head,*ip_rear;
    query_domain *dom,*dom_head,*dom_rear, *dom_helper;
    domains *t_domains, *t_domains_helper;
    d_2_ip *domain_ip_list, *domain_ip_list_helper;
    int domain_count;
    int t_level = -1;

    ip_head = ip_rear = NULL;
    dom_head = dom_rear =  NULL;
   
    for(cnt = 0; cnt < num; cnt++){
        t_query = blackMole->qlist_head;
        list_domain= search_domain(t_query->dname,blackMole->root_list);

        if(list_domain)
            t_level = list_domain->suspicious;

        if(ip_head == NULL){
            ip_head = ip_rear = ip_new(t_query->srcip,t_query->dname,t_level);
        }
        else{
            if(!(t_ip = search_ip(ip_head,t_query->srcip))){
                if((domain_count = return_count(t_ip,t_query->dname)) > 0){
                    add_count(t_ip,t_query->dname);
                }
                else{
                    ip_add_domain(t_ip,t_query->dname,t_level);
                }
            }   
            else{
                t_ip = ip_new(t_query->srcip,t_query->dname,t_level);
                ip_rear->next = t_ip;
                t_ip->prev = ip_rear;
                ip_rear = t_ip;
            }
        }  
         
        if(t_level >= 0){
            t_ip->num++;
            t_ip->sum += t_level;
        }

        if(dom_head == NULL){
            dom_head = dom_rear = new_query_domain(t_query->dname);
        }
        else{
            if((dom = find_by_name(dom_head,t_query->dname)) != 0){
                add_ip_2_domain(dom,(void *)t_ip);
            }
            else{
                dom = new_query_domain(t_query->dname);
                dom->prev = dom_rear;
                dom_rear->next = dom;
                dom_rear = dom;
            }
        }
                
        blackMole->qlist_head = blackMole->qlist_head->next;
        query_remove(t_query);
    }

    float index = 0;

    for(cnt = 0; cnt < 2; cnt++){
        dom = dom_head;
        while(dom){
            if(dom->type <= 0.1){
                domain_ip_list = dom->ip;
                while(domain_ip_list){
                    domain_count = domain_ip_list->count;
                    domain_ip_list->ip->num -= domain_count;
                    ip_remove_domain(domain_ip_list->ip,dom->name);
                    domain_ip_list = domain_ip_list->next;
                }
                remove_domain(dom);
            }
            else(dom->type == -1 && cnt == 1){
                index = 0.0;
                dom_helper = dom_head;
                while(dom_helper){
                    if(dom_helper >= 0.9){
                        domain_ip_list_helper = dom_helper->ip;
                        index += calculate_blacklist_heuristics(dom_ip_list_helper,dom_ip_list);
                    }
                    dom_helper = dom_helper->next;
                }

                // do something with index;
            }

            dom = dom->next;
        }
    }

   clean_domain_structure(dom_head);
   clean_ip_structure(ip_head);
}

float calculate_blacklist_heuristics(void *bad,struct void *good){

}

