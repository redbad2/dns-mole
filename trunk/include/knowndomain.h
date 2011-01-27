/* knowndomain.h

                    
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

#ifndef DNM_KNOWNDOMAIN_H
#define DNM_KNOWNDOMAIN_H

struct KnownDomain {
    char *name;
    int name_length;
    struct KnownDomain *kd_child;
    struct KnownDomain *next;
    struct KnownDomain *prev;
    int suspicious;
    unsigned int domain_hash;

    void *method_data;
};

typedef struct KnownDomain kdomain;

kdomain *add_domain(kdomain *, kdomain *, int );
void delete_domain(kdomain *);
void domain_child_free(kdomain *);
void check_domain(int *, char *, kdomain *, int, int);
kdomain *search_domain(char *, kdomain *, int);
kdomain *new_domain_structure(char *, int);
void load_domain(char *, kdomain *, int);
void split_domain(char *, char **);
void read_list(void *,kdomain *, char *, int);
unsigned int hash(const char *, int);

#endif
