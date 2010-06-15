#include "query.h"
#include "error.h"

void qlist_init() {
	qlist.head = malloc(sizeof(qentry));
	qlist.head->qe_qry = NULL;
	qlist.rear = qlist.head;
}

qentry * qlist_next(qentry * q) {
	return q->qe_next;
}

int qlist_insert(query * q) {
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

void qlist_delete(qentry * q) {
	if (q == qlist.head) {
		qentry * next = q->qe_next;
		free(q->qe_qry->q_value);
		free(q->qe_qry);
		free(q);
		next->qe_prev = NULL;
		qlist.head = next;
	}
	else if (q == qlist.rear) {
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
