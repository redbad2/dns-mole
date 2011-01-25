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

void openLog(void *t,const char *name){

    moleWorld *mW = (moleWorld *) t;
    time_t now = time(NULL);

    if((mW->log_fp = fopen(name,"a+")) == NULL){
            fprintf(stderr,"[fopen] Can't open log file\n"); 
            exit(EXIT_FAILURE);
    }

    fprintf(mW->log_fp,"[dns-mole] Log Started : %s", asctime(localtime(&now)));
    fflush(mW->log_fp);
}


void closeLog(void *t){
    
    moleWorld *mW = (moleWorld *) t;
    time_t now = time(NULL);

    fprintf(mW->log_fp,"[dns-mole] Log Closed: %s", asctime(localtime(&now)));

    if(fclose(mW->log_fp)){
        fprintf(stderr,"[fclose] Can't close log file\n"); exit(EXIT_FAILURE);
    }
    fflush(mW->log_fp);
}

void report(FILE *fp,char *d_name_1,char *d_name_2,unsigned int ip,int method,int type,char *additional){
    
    time_t rawtime;
    struct tm *timeinfo;
    char timeBuf[80];

    char method_string[20];
    char message[120]; memset(message,'\0',120);
    struct in_addr report_ip;
    
    if(type != 4){
        if(!ip){
            if(d_name_2){
                snprintf(message,120,"Domains: {%s , %s} added",d_name_1,d_name_2);
            } else
                snprintf(message,120,"Domain: (%s) added",d_name_1);
        } else {
            report_ip.s_addr = ip;
            if(d_name_2 && d_name_1){
                snprintf(message,120,"Ip: [%s] - {%s , %s}",inet_ntoa(report_ip),d_name_1,d_name_2);
            } else if(!d_name_2 && d_name_1){
                snprintf(message,120,"Ip: [%s] - (%s)",inet_ntoa(report_ip),d_name_1);
            } else
                snprintf(message,120,"Ip: [%s]",inet_ntoa(report_ip));
        }
    }

    switch(method){
        case 1:
            strcpy(method_string,"COR");
            break;
        case 2:
            strcpy(method_string,"GA");
            break;
        case 3:
            strcpy(method_string,"FHS");
            break;
    }

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timeBuf,80,"[%x|%X]",timeinfo);

    if(type == 1)
        fprintf(fp,"[%s][%s][BL] %s\n",timeBuf,method_string,message);
    if(type == 2)
        fprintf(fp,"[%s][%s][WL] %s\n",timeBuf,method_string,message);
    if(type == 3)
        fprintf(fp,"[%s][%s][IP] %s\n",timeBuf,method_string,message);
    if(type == 4)
    	fprintf(fp, "%s",additional);

    fflush(fp);
}

