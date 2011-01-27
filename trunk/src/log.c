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

void openDB(void *t,const char *name){

    moleWorld *mW = (moleWorld *) t;

    if(sqlite3_open(name,&mW->db)){
        fprintf(stderr,"[Error] Can't open database: %s\n",sqlite3_errmsg(mW->db));
        sqlite3_close(mW->db); exit(EXIT_FAILURE);
    }
}

void closeDB(void *t){

    moleWorld *mW = (moleWorld *) t;

    sqlite3_close(mW->db);
}

void useDB(void *t,const char *query,...){
    
    moleWorld *mW = (moleWorld *) t;
    
    typedef int (*pointer_callback)(void *, int, char **, char **);
    pointer_callback dbCallBack;

    va_list args;
    int count = 0, rc;
    char new_query[255], *err;

    int int_temp;
    char *string_temp, char_temp;

    va_start(args,query);
    
    while(*query){
        if(*query == '?'){
            *query++;
            switch(*query){

                case 's':
                    string_temp = va_arg(args,char *);
                    memcpy(new_query + count,string_temp,strlen(string_temp));
                    count+=strlen(string_temp);
                    break;
                
                case 'c':
                    chart_temp = va_arg(args,char);
                    new_query[count++] = char_temp;
                    break;
  
                case 'i':
                    int_temp = va_arg(args,int);
                    snprintf(new_query,255,"%s%d",new_query,int_temp);
                    count=strlen(new_query);
                    break;

            }
            
            *query++;

        } else
            new_query[count++] = *query;
    }
    
    new_query[count] = '\0';   
    dbCallBack = va_arg(args,pointer_callback);

    va_end(args);

    /*
    if(dbCallBack != NULL)
        rc = sqlite3_exec(mW->db,new_query,dbCallBack,(void *) mW,&err);
    else
        rc = sqlite3_exec(mW->db,new_query,0,0,&err);
    
    if(err != SQLITE_OK){
        fprintf(stderr,"[SQL Error] %s\n",err);
        closeDB(mW); exit(EXIT_FAILURE);
    }
    */
    
}

/*  below functions will be descarded  */

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

