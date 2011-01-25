/* fhs-detection.c
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

void fhs_initialize(void *tMole){
    
    moleWorld *fhsMole = (moleWorld *) tMole;
    
    (fhsMole->analyze_tv).tv_sec = (fhsMole->parameters).s_analyze_interval;
    (fhsMole->moleFunctions).filter = fhs_filter;
    (fhsMole->moleFunctions).analyze = fhs_process;
}

int fhs_filter(void *q_filter){
	
	return 1;
}

void fhs_process(unsigned int n_pkt,void *tMole){
	
	int net_size = 1;
	st_host * list;
	query * q;
	moleWorld * sMole = (moleWorld *)tMole;

	q = sMole->qlist_head;
	list = st_new_host(q->srcip, q);
	q = q->next;
	int packet_count = 0;
	
	while (q != NULL) {
		if (st_add_query_to_list(list, q, sMole))
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
	report(sMole->log_fp,NULL,NULL,0,3, 4,"[Using statistics]\n");
	for (i = 0; i < select_num; i++) {
		st_cal(h[i], sMole);
		if (h[i]->abnormal_type == 0) normal++;
		else {
                printf(msg, "\t%s\t%s\n\t\ttotal: %d\tmx: %d\tptr: %d\n\t\ttime: %s\t\tt_total: %f\tt_balance: %f\n" 
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
			report(sMole->log_fp,NULL,NULL,0,3, 4, msg);
			//printf("%s", msg);
			bad++;
		}
	}

	sprintf(msg, "[%d] packets captured\n[%d] hosts selected\n[%d] total hosts\n[%d] abnormal\n", packet_count, select_num, net_size, bad);
	report(sMole->log_fp,NULL,NULL,0, 3, 4, msg);
	printf("%s", msg);
}
