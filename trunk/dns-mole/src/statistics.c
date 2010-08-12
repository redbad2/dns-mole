/* statistics.c
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

#include "../include/statistics.h"

void st_cal(st_host * host) {
	host->mean_qr = (float)host->total / host->interval_num;
	host->mean_ptr = (float)host->ptr_total / host->interval_num;
	host->mean_mx = (float)host->mx_total / host->interval_num;
	st_cal_dev(host);
	host->t_total = (host->total - host->mean_qr) / host->dev_qr;
	host->t_balance = (host->query_total - host->response_total) / host->total;
	if (host->t_balance < 0)
		host->t_balance = -host->t_balance;
	host->t_ptr = (host->ptr_total - host->mean_ptr) / host->dev_ptr;
	host->t_ptr_rate = (float)host->ptr_total / host->total;
	host->t_mx = (host->mx_total - host->mean_mx) / host->dev_mx;
	host->t_mx_rate = (float)host->mx_total / host->total;

	/* infected type to decide */
	if (host->t_total >= THRESHOLD_TOTAL)
		host->type |= 0x1;
	if (host->t_balance >= THRESHOLD_BALANCE)
		host->type |= 0x10;
	if (host->t_ptr >= THRESHOLD_PTR)
		host->type |= 0x100;
	if (host->t_ptr_rate >= THRESHOLD_PTR_RATE)
		host->type |= 0x1000;
	if (host->t_mx >= THRESHOLD_MX)
		host->type |= 0x10000;
	if (host->t_mx_rate >= THRESHOLD_MX_RATE)
		host->type |= 0x100000;
}

void st_cal_dev(st_host * host) {
	float dev_qr = 0;
	float dev_ptr = 0;
	float dev_mx = 0;
	float temp;
	st_num * num = host->num_head;
	while (num != NULL) {
		temp = (num->query_num + num->response_num) - host->mean_qr;
		temp *= temp;
		dev_qr += temp;

		temp = num->ptr_num - host->mean_ptr;
		temp *= temp;
		dev_ptr += temp;

		temp = num->mx_num - host->mean_mx;
		temp *= temp;
		dev_mx += temp;

		num = num->next;
	}
	host->dev_qr = sqrt(dev_qr);
	host->dev_ptr = sqrt(dev_ptr);
	host->dev_mx = sqrt(dev_mx);
}

void st_insert_num(st_host * host, st_num * num) {
	if (host->num_head == NULL) {
		host->num_head = host->num_rear = num;
		host->interval_num++;
		return;
	}
	else {
		host->num_rear->next = num;
		num->prev = host->num_rear;
		host->num_rear = num;
		host->interval_num++;
	}
}

void st_insert_num_before(st_host * host, st_num * num) {
	num->next = host->num_head;
	host->num_head->prev = num;
	host->num_head = num;
	host->interval_num++;
}

st_host * st_new_host(unsigned int ip) {
	st_host * host;
	if ((host = (st_host *)malloc(sizeof(st_host))) == NULL) {
		fprintf(stderr,"[malloc] OOM\n");
		exit(EXIT_FAILURE);
	}
	memset(host, 0, sizeof(st_host));
	host->ip = ip;
	return host;
}

int st_add_query_to_list(st_host * list, query * q) {
	st_host * host = list;
	while (host != NULL) {
		if (host->ip == q->srcip) {
			st_add_query_to_host(host, q);
			if (st_add_query_to_list_dst(list, q))
				return 1;
			else return 0;
		}  
		else if (host->ip == q->dstip) {
			st_add_query_to_host(host, q);
			if (st_add_query_to_list_src(list, q))
				return 1;
			else return 0;
		}
		host = host->next;
	}
	host = st_new_host(q->srcip);
	st_host_insert(list, host);
	st_add_query_to_host(host, q);
	return 1;
}

int st_add_query_to_list_src(st_host * list, query * q) {
	st_host * host = list;
	while (host != NULL) {
		if (host->ip == q->srcip) {
			st_add_query_to_host(host, q);
			return 0;
		}
		host = host->next;
	}
	host = st_new_host(q->srcip);
	st_host_insert(list, host);
	st_add_query_to_host(host, q);
	return 1;
}

int st_add_query_to_list_dst(st_host * list, query * q) {
	st_host * host = list;
	while (host != NULL) {
		if (host->ip == q->dstip) {
			st_add_query_to_host(host, q);
			return 0;
		}
		host = host->next;
	}
	host = st_new_host(q->dstip);
	st_host_insert(list, host);
	st_add_query_to_host(host, q);
	return 1;
}

void st_add_query_to_host(st_host * host, query * q) {
	/* find/allocate num for host */
	st_num * num;
	int new_num_flag = 0;
	int i;
	if (host->start_time == 0) {
		host->start_time = q->time;
		if ((num = (st_num *)malloc(sizeof(st_num))) == NULL) {
			fprintf(stderr,"[malloc] OOM\n");
			exit(EXIT_FAILURE);
		}
		memset(num, 0, sizeof(st_num));
		new_num_flag = 1;
	}
	else {
		int index = (q->time - host->start_time) / INTERVAL;
		if (index < 0) {
			host->start_time = q->time;
			while (index != 0) {
				index++;
				st_num * temp;
				if ((temp = (st_num *)malloc(sizeof(st_num))) == NULL) {
					fprintf(stderr,"[malloc] OOM\n");
					exit(EXIT_FAILURE);
				}
				memset(temp, 0, sizeof(st_num));
				st_insert_num_before(host, temp);
			}
			num = host->num_head;
		}
		else {
			num = host->num_head;
			while (index != 0 && num != NULL) {
				index--;
				num = num->next;
			}
			if (index != 0 && num == NULL) {
				while (index != 0) {
					index--;
					st_num * temp;
					if ((temp = (st_num *)malloc(sizeof(st_num))) == NULL) {
						fprintf(stderr,"[malloc] OOM\n");
						exit(EXIT_FAILURE);
					}
					memset(temp, 0, sizeof(st_num));
					st_insert_num(host, temp);
				}
				num = host->num_rear;
			}
		}
	}

	/* set fields of num */
	if (q->srcip == host->ip) {
		num->query_num++;
		host->query_total++;
	}
	else {
		num->response_num++;
		host->response_total++;
	}
	host->total++;
	
	for (i = 0; i < q->ansnum; i++) {
		switch(q->answers[i].type) {
		case RR_TYPE_MX:
			num->mx_num++;
			host->mx_total++;
			break;
		case RR_TYPE_PTR:
			num->ptr_num++;
			host->ptr_total++;
			break;
		default:
			continue;
		}
	}
	if (new_num_flag)
		st_insert_num(host, num);
}

void st_host_insert(st_host * list, st_host * host) {
	st_host * next = list->next;
	if (next != NULL) {
		list->next = host;
		host->prev = list;
		host->next = next;
		next->prev = host;
	}
	else {
		list->next = host;
		host->prev = list;
	}
}


void st_host_empty(st_host * list) {
	st_host * prev = list->prev;
	st_host * next = list->next;
	st_host * temp;
	st_host_free(list);
	while (prev != NULL) {
		temp = prev->prev;
		st_host_free(prev);
		prev = temp;
	}
	while (next != NULL) {
		temp = next->next;
		st_host_free(next);
		next = temp;
	}
}

void st_host_remove(st_host * host) {
	st_host * prev = host->prev;
	st_host * next = host->next;
	if (prev != NULL && next != NULL) {
		prev->next = next;
		next->prev = prev;
	}
	else if (prev != NULL) {
		prev->next = NULL;
	}
	else if (next != NULL) {
		next->prev = NULL;
	}
	st_host_free(host);
}

void st_host_free(st_host * host) {
	st_num * t = host->num_head;
	st_num * next;
	while (t != NULL) {
		next = t->next;
		free(t);
		t = next;
	}
	free(host);
}

