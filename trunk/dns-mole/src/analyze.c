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
                    
void blacklist_method(int num_packets,void *black){

    moleWorld *blackMole = (moleWorld *) black;
    int count;
    
    bl_ip *t_bl_ip,*bl_ip_head,*bl_ip_rear;
    bl_domain *bl_d_head, *bl_d_rear, *t_bl_domain;
    kdomain *domain_list;
    query *t_query;
    
    int t_type;

    bl_d_head = bl_d_rear = NULL;
   
    for(count = 0; count < num_packets; count++){
        t_type = -1;
        t_query = blackMole->qlist_head;
        domain_list = search_domain(t_query->dname,blackMole->root_list);

        if(domain_list)
            t_type = domain_list->suspicious;
        
            
        
        if(bl_ip_head == NULL){
            bl_ip_head = bl_ip_rear = new_bl_ip(t_query->srcip);
        }
            
        else{
		    if((t_bl_ip = find_ip(bl_ip_head,t_query->srcip)) == 0){
                t_bl_ip = new_bl_ip(t_query->srcip);
                bl_ip_rear->next = t_bl_ip;
                t_bl_ip->prev = bl_ip_rear;
                bl_ip_rear = t_bl_ip;
                }
        }  

        if(t_type == 1)
            t_bl_ip->black_hosts++;
        
        if(t_type == 0)
            t_bl_ip->white_hosts++;
        
        t_bl_ip->all_hosts++;

        if(t_type == -1 || t_type == 1){

            if(bl_d_head == NULL){
                bl_d_head = bl_d_rear = new_bl_domain(t_query->dname,t_type);
                add_ip_to_domain(bl_d_rear,(void *)t_bl_ip); 
            }
        
            else{
                if(!(t_bl_domain = find_domain(bl_d_head,t_query->dname))){
                    add_ip_to_domain(t_bl_domain,(void *)t_bl_ip);
                }
                else{
                    t_bl_domain = new_bl_domain(t_query->dname,t_type);
                    add_ip_to_domain(t_bl_domain,(void *)t_bl_ip);
                    t_bl_domain->prev = bl_d_rear;
                    bl_d_rear->next = t_bl_domain;
		            bl_d_rear = t_bl_domain;
                }
            }
        }

        blackMole->qlist_head = blackMole->qlist_head->next;
        query_remove(t_query);
    }

    float jaccard_index, index;
    int weight_infected, weight_all;
    bl_domain *t_domain_1, *t_domain_2;
    bl_domain_ip *t_domain_ip,*t_ip_for_change;

    t_domain_1 = bl_d_head;
    while(t_domain_1){
        if(t_domain_1->type == -1){
            jaccard_index = index = 0.0;
            weight_infected = weight_all = 0;
            t_domain_2 = bl_d_head;
            while(t_domain_2){
                if(t_domain_2->type != -1){
                    jaccard_index += calculate_jaccard_index(t_domain_1,t_domain_2);
                }
            t_domain_2 = t_domain_2->next; 
            }

            t_domain_ip = t_domain_1->domain_ip;
                
            while(t_domain_ip){
                if((float)(t_domain_ip->ip->black_hosts / t_domain_ip->ip->all_hosts) > 0.5 )
                    weight_infected += t_domain_ip->count;

                weight_all += t_domain_ip->count;
                t_domain_ip = t_domain_ip->next;
            }

            index = jaccard_index * (weight_infected/weight_all);
            if( index < 0.2 ){

            // we got some new white list domain for blacklist write that to log
                
                load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,0);
                
                t_ip_for_change = t_domain_1->domain_ip;
                while(t_ip_for_change){
                    t_bl_ip = find_ip(bl_ip_head,t_ip_for_change->ip->ip);
                    t_bl_ip->white_hosts += t_ip_for_change->count;
                    remove_domain(t_domain_1,0);
                    t_ip_for_change = t_ip_for_change->next;
                }
            }
            
            else if( index > 0.8 ){

            // new black domain write log add to structure

                load_domain(t_domain_1->d_name,blackMole->re,blackMole->root_list,1);
                
                t_ip_for_change = t_domain_1->domain_ip;
                while(t_ip_for_change){
                    t_bl_ip = find_ip(bl_ip_head,t_ip_for_change->ip->ip);
                    t_bl_ip->black_hosts += t_ip_for_change->count;
                    t_ip_for_change = t_ip_for_change->next;
                }
            }
        }

        t_domain_1 = t_domain_1->next;
    }

    t_bl_ip = bl_ip_head;
    
    while(t_bl_ip){
        if(((t_bl_ip->black_hosts/t_bl_ip->all_hosts) * (t_bl_ip->white_hosts/t_bl_ip->all_hosts)) <= 0.3){

            // write log that we indetify potential zombie host
        }
        t_bl_ip = t_bl_ip->next;
    }

    remove_domain(bl_d_head,1);
    remove_ip(bl_ip_head);
}

float calculate_jaccard_index(void *unknown,void *black){

    bl_domain *unknown_domain = (bl_domain *) unknown;
    bl_domain *black_domain = (bl_domain *) black;
    bl_domain_ip *black_domain_ip = black_domain->domain_ip;
    int numerator = 0, denominator = 0;

    while(black_domain_ip){
        if(find_ip_in_domain(unknown_domain->domain_ip,black_domain_ip->ip->ip))
            numerator++;
        black_domain_ip = black_domain_ip->next;
    }

    denominator = black_domain->queried_overall + unknown_domain->queried_overall;

    return (numerator/denominator);
}
