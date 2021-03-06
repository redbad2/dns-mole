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

#include "dnsmole.h" 

void query_insert(query * q1, query *q2) {
    query * next = q1->next;
    if (next != NULL) {
        q1->next = q2; 
        q2->prev = q1;
        q2->next = next;
        next->prev = q2;
    }
    else {
        q1->next = q2;
        q2->prev = q1;
    }
    
}

void query_remove(query *q) {

    query *prev = q->prev;
    query *next = q->next;

    if (prev != NULL && next != NULL) {
	prev->next = next;
	next->prev = prev;
    }
    else if (prev != NULL)
	prev->next = NULL;
    else if (next != NULL)
	next->prev = NULL;
	
    free(q->answers);
    free(q->authority);
    free(q->additional);
    free(q);
}


