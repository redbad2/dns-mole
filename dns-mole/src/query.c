/* query.c
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

#include <stdlib.h>
#include "../include/query.h"
#include "../include/error.h"


void qlist_init(qlist * ql){
	
	ql->head = (qentry *) malloc(sizeof(qentry));
	ql->head->qe_qry = NULL;
	ql->rear = ql->head;
}

void qlist_reset(qlist * ql) {
	
	if (ql->head == NULL)
		return;
		
	qentry *q = ql->head;
	qentry *p = q;
	
	while (q != NULL) {
		p = q->qe_next;
		free(q->qe_qry->q_answers);
		free(q->qe_qry);
		free(q);
		q = p;
	}
	
	ql->head = NULL;
	ql->rear = NULL;
}

int qlist_append(qlist * ql, query * q){

	if (ql->head->qe_qry == NULL){
		ql->head->qe_qry = q;
		ql->head->qe_next = NULL;
		ql->head->qe_prev = NULL;
		ql->rear = ql->head;
	}
	else{
		qentry *temp = (qentry *)malloc(sizeof(qentry));
		
		if (temp == NULL)
			return E_NO_MEM;
			
		temp->qe_qry = q;
		temp->qe_next = NULL;
		temp->qe_prev = ql->rear;
		ql->rear->qe_next = temp;
		ql->rear = temp;
	}
	
	return 0;
}


int qlist_insert_before(qlist * ql, qentry * qe, query * q){
	
	if (qe == ql->head) {
		qentry *temp = (qentry *)malloc(sizeof(qentry));
		
		if (temp == NULL)
			return E_NO_MEM;
			
		temp->qe_qry = q;
		temp->qe_next = qe;
		temp->qe_prev = NULL;
		qe->qe_prev = temp;
		ql->head = temp;
	}
	else{
		qentry *temp = (qentry *)malloc(sizeof(qentry));
		
		if (temp == NULL)
			return E_NO_MEM;
			
		temp->qe_qry = q;
		temp->qe_next = qe;
		
		qentry * p = qe->qe_prev;
		temp->qe_prev = p;
		qe->qe_prev = temp;
		p->qe_next = temp;
	}
}


int qlist_insert_after(qlist * ql, qentry * qe, query * q){
	
	if (qe == ql->rear) {
		qentry *temp = (qentry *)malloc(sizeof(qentry));
		
		if (temp == NULL)
			return E_NO_MEM;
			
		temp->qe_qry = q;
		temp->qe_prev = qe;
		temp->qe_next = NULL;
		qe->qe_next = temp;
		ql->rear = temp;
	}
	else{
		qentry * temp = (qentry *)malloc(sizeof(qentry));
		
		if (temp == NULL)
			return E_NO_MEM;
			
		temp->qe_qry = q;
		temp->qe_prev = qe;
		
		qentry *p = qe->qe_next;
		temp->qe_next = p;
		qe->qe_next = temp;
		p->qe_prev = temp;
	}
}

void qlist_remove(qlist * ql, qentry * q){

	if (q == ql->head){
		
		if (ql->head == ql->rear){
			qlist_reset(ql);
			return;
		}
		
		qentry *next = q->qe_next;
		free(q->qe_qry->q_answers);
		free(q->qe_qry);
		free(q);
		next->qe_prev = NULL;
		ql->head = next;
	}
	else if (q == ql->rear){
		
		if (ql->head == ql->rear) {
			qlist_reset(ql);
			return;
		}
		
		qentry *prev = q->qe_prev;
		free(q->qe_qry->q_answers);
		free(q->qe_qry);
		free(q);
		prev->qe_next = NULL;
		ql->rear = prev;
	}
	else{
		qentry *next = q->qe_next;
		qentry *prev = q->qe_prev;
		free(q->qe_qry->q_answers);
		free(q->qe_qry);
		free(q);
		next->qe_next = prev;
		prev->qe_prev = next;
	}
}

