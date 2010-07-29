#include <stdio.h>
#include "../include/query.h"

void print(query * q) {
	int i;
	while (q != NULL) {
		if (q == NULL) {
			q = q->next;
			continue;
		}
		printf("%s\n", q->dname);
		printf("\tTIME %d", (int)q->time);
		printf("\tSRC_IP %s\n", (char *)inet_ntoa(q->srcip));
		printf("\tANS_NUM %d\n", q->ansnum);
		for (i = 0; i < q->ansnum; i++) {
			printf("\t\tTTL %d\n", q->answers[i].ttl);
			printf("\t\tTYPE %d\n", q->answers[i].type);
			if (q->answers[i].type == RR_TYPE_A)
				printf("\t\tVALUE %s\n", (char *)inet_ntoa(q->answers[i].value));
			else
				printf("\t\tVALUE %s\n", q->answers[i].value);
		}
		q = q->next;
	}
}
