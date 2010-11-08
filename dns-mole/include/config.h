/* config.h
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

#ifndef DNM_CONFIG_H
#define DNM_CONFIG_H

struct configuration{
    char *variable;
    void *where;
    int type;
    struct configuration *next;
};

typedef struct configuration configuration;

configuration *create_t_configuration(const char *, void *, int);
configuration *set_config(void *);
void register_config(configuration *, const char *, void *, int);
void read_config(const char *, configuration *);

#endif
