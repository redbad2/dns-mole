/* statistics.h
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

#ifndef DNSM_STATISTICS_H
#define DNSM_STATISTICS_H

#define THRESHOLD_TOTAL 5
#define THRESHOLD_PTR 5
#define THRESHOLD_MX 5

#define THRESHOLD_BALANCE 0.9
#define THRESHOLD_PTR_RATE 0.9
#define THRESHOLD_MX_RATE 0.9

#define INTERVAL 60

#include "query.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct st_num {
	int query_num;
	int response_num;
	int mx_num;
	int ptr_num;
	struct st_num * next;
	struct st_num * prev;
} st_num;

typedef struct st_host {
	unsigned int ip;
	int total;
	int query_total;
	int response_total;
	int mx_total;
	int ptr_total;
	int interval_num;

	st_num * num_head;
	st_num * num_rear;
	int start_time;

	float dev_qr;
	float mean_qr;
	float dev_ptr;
	float mean_ptr;
	float dev_mx;
	float mean_mx;

	float t_total;
	float t_balance;
	float t_ptr;
	float t_ptr_rate;
	float t_mx;
	float t_mx_rate;

	int type;

	struct st_host * prev;
	struct st_host * next;
} st_host;

void st_cal(st_host * host);
void st_cal_dev(st_host * host);

void st_insert_num(st_host * host, st_num * num);
void st_insert_num_before(st_host * host, st_num * num);

st_host * st_new_host(unsigned int ip);
int st_add_query_to_list(st_host * list, query * q);
int st_add_query_to_list_src(st_host * list, query * q);
int st_add_query_to_list_dst(st_host * list, query * q);
void st_add_query_to_host(st_host * host, query * q);
void st_host_insert(st_host * list, st_host * host);
void st_host_empty(st_host * list);
void st_host_remove(st_host * host);
void st_host_free(st_host * host);

#endif
