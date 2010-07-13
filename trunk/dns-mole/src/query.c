#include "../include/query.h"
#include "../include/error.h"
#include <stdlib.h>

void qlist_init() {
	qlist.head = malloc(sizeof(qentry));
	qlist.head->qe_qry = NULL;
	qlist.rear = qlist.head;
}

void qlist_reset() {
	if (qlist.head == NULL)
		return;
	qentry * q = qlist.head;
	qentry * p = q;
	while (q != NULL) {
		p = q->qe_next;
		free(q->qe_qry->q_value);
		free(q->qe_qry);
		free(q);
		q = p;
	}
	qlist.head = NULL;
	qlist.rear = NULL;
}

int qlist_append(query * q) {
	if (qlist.head->qe_qry == NULL) {
		qlist.head->qe_qry = q;
		qlist.head->qe_next = NULL;
		qlist.head->qe_prev = NULL;
		qlist.rear = qlist.head;
	}
	else {
		qentry * temp = (qentry *)malloc(sizeof(qentry));
		if (temp == NULL)
			return E_NO_MEM;
		temp->qe_qry = q;
		temp->qe_next = NULL;
		temp->qe_prev = qlist.rear;
		qlist.rear->qe_next = temp;
		qlist.rear = temp;
	}
	return 0;
}


int qlist_insert_before(qentry * qe, query * q) {
	if (qe == qlist.head) {
		qentry * temp = (qentry *)malloc(sizeof(qentry));
		if (temp == NULL)
			return E_NO_MEM;
		temp->qe_qry = q;
		temp->qe_next = qe;
		temp->qe_prev = NULL;
		qe->qe_prev = temp;
		qlist.head = temp;
	}
	else {
		qentry * temp = (qentry *)malloc(sizeof(qentry));
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


int qlist_insert_after(qentry * qe, query * q) {
	if (qe == qlist.rear) {
		qentry * temp = (qentry *)malloc(sizeof(qentry));
		if (temp == NULL)
			return E_NO_MEM;
		temp->qe_qry = q;
		temp->qe_prev = qe;
		temp->qe_next = NULL;
		qe->qe_next = temp;
		qlist.rear = temp;
	}
	else {
		qentry * temp = (qentry *)malloc(sizeof(qentry));
		if (temp == NULL)
			return E_NO_MEM;
		temp->qe_qry = q;
		temp->qe_prev = qe;
		
		qentry * p = qe->qe_next;
		temp->qe_next = p;
		qe->qe_next = temp;
		p->qe_prev = temp;
	}
}

void qlist_remove(qentry * q) {
	if (q == qlist.head) {
		if (qlist.head == qlist.rear) {
			qlist_reset();
			return;
		}
		qentry * next = q->qe_next;
		free(q->qe_qry->q_value);
		free(q->qe_qry);
		free(q);
		next->qe_prev = NULL;
		qlist.head = next;
	}
	else if (q == qlist.rear) {
		if (qlist.head == qlist.rear) {
			qlist_reset();
			return;
		}
		qentry * prev = q->qe_prev;
		free(q->qe_qry->q_value);
		free(q->qe_qry);
		free(q);
		prev->qe_next = NULL;
		qlist.rear = prev;
	}
	else {
		qentry * next = q->qe_next;
		qentry * prev = q->qe_prev;
		free(q->qe_qry->q_value);
		free(q->qe_qry);
		free(q);
		next->qe_next = prev;
		prev->qe_prev = next;
	}
}
