/* knowndomain.c
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
    
#define FALSE 0

kdomain *add_domain(kdomain *new_domain,kdomain *search_domain,int level){
    kdomain *tdomain = search_domain;
    if(!strcmp(search_domain->name,"ROOT") && !search_domain->kd_child){
        search_domain->kd_child = new_domain;
        search_domain->next = NULL;
        search_domain->prev = NULL;
        search_domain->kd_child->prev = search_domain;
        tdomain = search_domain->kd_child;
    }
    else if(!strcmp(search_domain->name,"ROOT") && search_domain->kd_child){
        tdomain = search_domain->kd_child;
    }
    else if(!strcmp(search_domain->name,"TEMP")){
        new_domain->prev = search_domain->prev;
        search_domain->prev->kd_child = new_domain;
        tdomain = new_domain;
    }

    while(tdomain){
        if(!strcmp(tdomain->name,new_domain->name) && tdomain->kd_child){
            return tdomain->kd_child;
        }
        else if(!strcmp(tdomain->name,new_domain->name) && !tdomain->kd_child){
            if(level == 1){
                tdomain->kd_child = new_domain_structure("TEMP",-1);
                tdomain->kd_child->prev = tdomain;
                return tdomain->kd_child;
            }
            else 
                return tdomain;
            
        }
        else if(!tdomain->next){
            tdomain->next = new_domain;
            tdomain->next->prev = tdomain; 
            tdomain = tdomain->next;
        }
        else if(tdomain->next){
            tdomain = tdomain->next;
        }
    }
    return (kdomain *) 0;
}

void delete_domain(kdomain *domain){
    domain->prev = domain->next;

    domain_child_free(domain->kd_child);
    if(domain->name) 
	free(domain->name);
    if(domain->method_data)
        free(domain->method_data);
    
    free(domain);
}

void domain_child_free(kdomain *domain_free){
    
    if(domain_free){
        domain_child_free(domain_free->kd_child);
        if(domain_free->name) 
	    free(domain_free->name);
        if(domain_free->method_data)
    	    free(domain_free->method_data);
        domain_child_free(domain_free->next);
        free(domain_free);
    }
}

kdomain *search_domain(char *name,kdomain *root_domain,int search_type){

    char **split_structure = malloc(sizeof(char *) * 4);
    int count = 0, len_size = 0;
    unsigned int temp_hash = 0;
    kdomain *temp_domain = root_domain->kd_child;

    if(!temp_domain){
        return (kdomain *) 0;
    }
    
    split_domain(name,split_structure);
    
    if(!split_structure[0]){
        return (kdomain *) 0;  
    }
    
    while(temp_domain){
        temp_hash = 0;
         
        if((len_size = strlen(split_structure[count])) <= 10){
            temp_hash = hash(split_structure[count],len_size);
        } else
            temp_hash = hash(split_structure[count],10);
    
        if(((temp_domain->domain_hash == temp_hash))){

            len_size = (temp_domain->name_length <= len_size ? temp_domain->name_length : len_size);
            
            if(!memcmp(temp_domain->name,split_structure[count],len_size)){
                
                if((temp_domain->suspicious == 0) && (search_type == 0)){
                    return temp_domain;
                }
                
                else if((count != 3) && (split_structure[count+1] != NULL)){
                    count++; 
                    temp_domain = temp_domain->kd_child;
                } 
                else if(count != 3 && split_structure[count+1] == NULL){
                    return temp_domain;
                }
                else if(count == 3){
                    return temp_domain;
                }
            }
            else
                temp_domain = temp_domain->next;
        }
        else 
            temp_domain = temp_domain->next;
        
    }
    free(split_structure);
    return (kdomain *)0;
}

kdomain *new_domain_structure(char *name,int suspicious){
    
    kdomain *tmp_domain;

    if((tmp_domain = (kdomain *) malloc(sizeof(kdomain))) != NULL){
        if((tmp_domain->name = malloc(strlen(name) * sizeof(char) +1)) == NULL){
           fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE); 
        }
        memcpy(tmp_domain->name,name,strlen(name)+1);
        tmp_domain->kd_child = tmp_domain->next = tmp_domain->prev = NULL;
        tmp_domain->suspicious = suspicious;
        tmp_domain->name_length = strlen(name);
        tmp_domain->method_data = NULL;
        tmp_domain->domain_hash = (tmp_domain->name_length <= 10 ? hash(name,tmp_domain->name_length): hash(name,10));
    }

    else{ 
        fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
    }

    return tmp_domain;
}
    
void load_domain(char *line,kdomain *domain,int type){

    kdomain *temp_domain = domain, *new_domain,*s_domain;
    
    if((s_domain = search_domain(line,domain,type))){
        if(s_domain->suspicious != type)
            s_domain->suspicious = type;
    } else {
        int i = 1;
        int splitcount;
        char **split_structure = malloc(sizeof(char *) * 4);;
        split_domain(line,split_structure);
        for(splitcount = 0; splitcount < 4;splitcount++){
            if(split_structure[splitcount] != NULL){
                if(split_structure[splitcount+1] == NULL){
                    new_domain = new_domain_structure(split_structure[splitcount],type);
                }
                else
                    new_domain = new_domain_structure(split_structure[splitcount],-1);

                if(split_structure[splitcount+1] == NULL)
                    i = 0;
                temp_domain = add_domain(new_domain,temp_domain,i);
                free(split_structure[splitcount]);
            }
        }

        free(split_structure);
    }

}

void split_domain(char *line,char **split_structure){
    
    char *substring, *split_substring;
    int length;
    int count, reverse = 0;
    int i;
    
    split_substring = strdup(line);
    count = strlen(split_substring);
    
    if(split_substring[count-1] == '\n'){
        split_substring[count-1] = '\0'; count--;
    }

    while(((reverse != 3) && (count != 0)) ){
        if((split_substring[count] == '.')){
            reverse++; split_substring[count] = '\0';
        }

        count--;
    }

    for(i = 0; i <= reverse; i++){
        substring = strdup(split_substring);
        length = strlen(substring);
        if((split_structure[reverse-i] = (char *)malloc(sizeof(char)*length+1)) == NULL){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        memcpy(split_structure[reverse-i],substring,length+1);
        split_substring = split_substring + length+1;
    }
    
    for(; i < 4; i++)
        split_structure[i] = NULL;
}
    
void read_list(kdomain *root,char *bl_filename,int type){
	
    FILE *fp; char line[80];
	if((fp = fopen(bl_filename,"r")) != NULL){
		while(fgets(line,sizeof(line),fp) != NULL){
			if(isalpha(line[0]) || isdigit(line[0]))
            		    load_domain(line,root,type);
		}
	}
	
    fclose(fp);
}


unsigned int hash(const char *str, int len){
    
    unsigned hash = 0;
    int count = 0;
    
    for(count = 0; count < len; count++)
        hash = (int) str[count] + (hash << 6) + (hash << 16) - hash;

    return (hash & 0x7FFFFFFF);
}
