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
 
#include "../../include/dnsmole.h"

void naive_initialize(void *tMole){

    moleWorld *naiveMole = (moleWorld *) tMole;

    (naiveMole->analyze_tv).tv_sec = (naiveMole->parameters).naive_analyze_interval;
    (naiveMole->moleFunctions).filter = naive_filter;
    (naiveMole->moleFunctions).analyze = naive_process;
}

int naive_filter(void *q_filter){

    query *query_filter = (query *) q_filter;

    if((query_filter->is_answer == 0) && (query_filter->q_type == 1)){
        return 1;
    }

    return 0;
}

void naive_process(unsigned int n_pkt,void *tMole){
	
}
