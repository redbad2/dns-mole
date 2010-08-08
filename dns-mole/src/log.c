/* log.c
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

#include "../include/dnsmole.h"

void open_log(void *t,const char *name){

    moleWorld *mW = (moleWorld *) t;
    time_t now = time(NULL);

    if((mW->log_fp = fopen(name,"a+")) == NULL){
            fprintf(stderr,"[fopen] Can't open log file\n"); 
            exit(EXIT_FAILURE);
    }

    fprintf(mW->log_fp,"[dns-mole] Log Started : %s", asctime(localtime(&now)));
}


void close_log(void *t){
    
    moleWorld *mW = (moleWorld *) t;
    time_t now = time(NULL);

    fprintf(mW->log_fp,"[dns-mole] Log Closed: %s", asctime(localtime(&now)));

    if(fclose(mW->log_fp)){
        fprintf(stderr,"[fclose] Can't close log file\n"); exit(EXIT_FAILURE);
    }
}

void write_log(FILE *fp,int type,const char *msg){
    
    fprintf(fp,"%d - %s\n",type,msg);
    fflush(fp);
}

