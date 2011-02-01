/* detection.h
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

#ifndef DETECTION_H
#define DETECTION_H

#include "dnsmole.h"
#include "qss.h"

void cor_initialize(void *tMole);
int cor_filter(void *q_filter);
void cor_process(unsigned int n_pkt,void *tMole);
void cor_analyze(void *domain,void **ip,void *mWorld);
float calculate_jaccard_index(void *unknown,void *black);

void ga_initialize(void *tMole);
int ga_filter(void *q_filter);
void ga_process(unsigned int n_pkt,void *tMole);
void ga_analyze(void *domain_list_one,void *domain_list_two,void *mWorld);

void naive_initialize(void *tMole);
int naive_filter(void *q_filter);
void naive_process(unsigned int n_pkt,void *tMole);

#endif

