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

#include "../include/analyze.h"
#include "../include/dnsmole.h"

void _learn(int fd,short event,void *arg){
    
    moleWorld *myMole= (moleWorld *) arg;

    switch(myMole->type){
        case 1:
            fprintf(stdout,"calculate parameters for entropy detection\n");
            break;
        case 2:
            fprintf(stdout,"calculate parameters for wavelet detection\n");
            break;
    }
    
    event_add(&myMole->analyze_ev,&myMole->analyze_tv);
}

void _analyzer(int fd,short event,void *arg){

    moleWorld *analyzeMole = (moleWorld *) arg;
    int num_packets = analyzeMole->count;

    kdomain *temp_domain;
    analyzeMole->count = 0;

    int count = 0;

    /* for(count = 0; count < num_packets; count++){
        if((temp_domain = search_domain(q_temp->qe_qry->q_dname,analyzeMole->root_list)) != NULL){
            if(temp_domain->type == 1){
               
                temp_domain->last_seen = time(NULL);
            }
            else if(temp_domain->type == ){
            }

            q_temp = q_temp->next;
            q_temp->prev = qtemp->prev->prev;
            free(q_temp->prev);
        }
    */
    //write_log(analyzeMole->log_fp,1,"heha");
    event_add(&analyzeMole->analyze_ev,&analyzeMole->analyze_tv);
}


