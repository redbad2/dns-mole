/* analyze.h
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

#ifndef DNM_ANALYZE_H
#define DNM_ANALYZE_H

void _analyzer(int , short , void *);

int is_domain_name_valid(const char *);
void populate_store_structure(int , void *, int);

void statistics_method(int , void *); 
void second_method(void *, void *, void *);
void first_method(void *, void **, void *);
float calculate_jaccard_index(void *, void *);

#endif
