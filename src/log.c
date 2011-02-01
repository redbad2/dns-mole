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


#define CREATE_domainLIST "CREATE TABLE domainList(id INTEGER PRIMARY KEY, name TEXT, type SMALLINT)"
#define CREATE_gaDomain "CREATE TABLE gaDomain(id INTEGER PRIMARY KEY,date DATE, name TEXT, type SMALLINT)"
#define CREATE_corDomain "CREATE TABLE corDomain(id INTEGER PRIMARY KEY,date DATE, name TEXT, type SMALLINT)"
#define CREATE_gaDomainRelation "CREATE TABLE gaDomainRelation(id INTEGER PRIMARY KEY, date DATE, domain1 TEXT, domain2 TEXT)"
#define CREATE_corIP "CREATE TABLE corIp(id INTEGER PRIMARY KEY,date DATE,ip TEXT)"

void openDB(void *t,const char *name){

    moleWorld *mW = (moleWorld *) t;
    int create = 0;

    if(access(name,F_OK) == -1)
        create = 1;

    if(sqlite3_open(name,&mW->db)){
        fprintf(stderr,"[Error] Can't open database: %s\n",sqlite3_errmsg(mW->db));
        sqlite3_close(mW->db); exit(EXIT_FAILURE);
    }

    if(create){
        useDB((void *)mW,CREATE_domainLIST);
        useDB((void *)mW,CREATE_gaDomain);
        useDB((void *)mW,CREATE_corDomain);
        useDB((void *)mW,CREATE_gaDomainRelation);
        useDB((void *)mW,CREATE_corIP);
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
    char *string_temp;

    memset(new_query,'\0',255);

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
                    int_temp = va_arg(args,int);
                    new_query[count++] = (char) int_temp;
                    break;
  
                case 'i':
                    int_temp = va_arg(args,int);
                    snprintf(new_query+count,255,"%d",int_temp);
                    count=strlen(new_query);
                    break;

            }
            
            *query++;

        } else
            new_query[count++] = *query++;
    }
  
    new_query[count] = '\0';   
    dbCallBack = va_arg(args,pointer_callback);

    va_end(args);
    
    if(dbCallBack != NULL)
        rc = sqlite3_exec(mW->db,new_query,dbCallBack,(void *) mW,&err);
    else
        rc = sqlite3_exec(mW->db,new_query,0,0,&err);
    
    if(err != SQLITE_OK){
		printf("%s\n",new_query);
        fprintf(stderr,"[SQL Error] %s\n",err);
        sqlite3_free(err); closeDB(mW); exit(EXIT_FAILURE);
    }    
}
