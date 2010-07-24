#include <stdio.h>
#include "../include/query.h"

void print2file(qlist * ql) {
	FILE * file = fopen("qlist_info.txt", "w");
	qentry * q = ql->head;
	int i;
	while (q != NULL) {
		if (q->qe_qry == NULL) {
			q = q->qe_next;
			continue;
		}
		fprintf(file, "%s\n", q->qe_qry->q_dname);
		fprintf(file, "\tTIME %d", (int)q->qe_qry->q_time);
		fprintf(file, "\tSRC_IP %s\n", (char *)inet_ntoa(q->qe_qry->q_srcip));
		fprintf(file, "\tANS_NUM %d\n", q->qe_qry->q_ansnum);
		for (i = 0; i < q->qe_qry->q_time; i++) {
			fprintf(file, "\t\tTTL %d\n", q->qe_qry->q_answers[i].ttl);
			fprintf(file, "\t\tTYPE %d\n", q->qe_qry->q_answers[i].type);
			if (q->qe_qry->q_answers[i].type == RR_TYPE_A)
				fprintf(file, "\t\tVALUE %s\n", (char *)inet_ntoa(q->qe_qry->q_answers[i].value));
			else
				fprintf(file, "\t\tVALUE %s\n", q->qe_qry->q_answers[i].value);
		}
		q = q->qe_next;
	}
	fclose(file);
}
