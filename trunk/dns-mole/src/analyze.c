/* analyze.c
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

#include "../include/analyze.h"
#include "../include/dnsmole.h"

void _learn(int fd,short event,void *arg){
    
    moleWorld *myMole= (moleWorld *) arg;

    switch(myMole->type){
        case 0:
            fprintf(stdout,"calculate parameters for entropy detection\n");
            break;
        case 1:
            fprintf(stdout,"calculate parameters for wavelet detection\n");
            break;
    }
}

void _analyzer(int fd,short event,void *arg){

    moleWorld *analyzeMole = (moleWorld *) arg;
    
    //analyzeMole.analyze_tv.tv_sec ='
    event_add(&analyzeMole->analyze_ev,&analyzeMole->analyze_tv);
}
