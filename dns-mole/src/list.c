#include "../include/knowndomain.h"
#include "../include/types.h"

#include <stdio.h>
#include <string.h>
#include <pcre.h>

kdomain *add_domain(kdomain *new_domain,kdomain *search_domain,int32 level){

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
            if(level != 1){
                tdomain->kd_child = new_domain_structure("TEMP");
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
}

kdomain *new_domain_structure(char *name){
    
    kdomain *tmp_domain;

    if((tmp_domain = (kdomain *) malloc(sizeof(kdomain))) != NULL){
        if((tmp_domain->name = malloc(strlen(name) * sizeof(name) +1)) == NULL){
            warn_quit("OOM");
        }
        memcpy(tmp_domain->name,name,strlen(name));
        tmp_domain->kd_child = tmp_domain->next = tmp_domain->prev = NULL;
        tmp_domain->suspicious = FALSE;
    }

    else{ 
        warn_quit("OOM"); 
    }

    return tmp_domain;
}

void load_url(char *line,pcre *re,kdomain *domain,int32 type){

    int32 vector[15]; char *substring, *nice_substring;
    int32 rc,i,substring_length; 
    kdomain *temp_domain = domain, *new_domain;

    rc = pcre_exec(re,NULL,line,strlen(line),0,0,vector,15);
    for(i = rc-1; i >= 1; i--){
        substring = line + vector[2*i];
        substring_length = vector[2*i+1] - vector[2*i];
        nice_substring = strdup(substring); 
        *(nice_substring + substring_length) = '\0';
        if(substring_length){
            if(i == 1) 
                nice_substring[strlen(nice_substring)-1] = '\0';
            new_domain = new_domain_structure(nice_substring);
            temp_domain = add_domain(new_domain,temp_domain,i);

        }
    }
    if(!strcmp(temp_domain->name,"TEMP")){
        temp_domain->prev->suspicious = type;
    }
    else{
        temp_domain->suspicious = type;
    }
}

void read_list(kdomain *root,const char *bl_filename,int32 type){
	
        FILE *fp; char line[80];
        pcre *re; const char *error; int32 error_offset;
        
        re = pcre_compile("([a-z0-9\\.]*?)([a-z0-9]*?)\\.?([a-z0-9]+)\\.([a-z0-9]+)$",0,&error,&error_offset,NULL);
	if((fp = fopen(bl_filename,"r")) != NULL){
		while(fgets(line,sizeof(line),fp) != NULL){
			if(line[0] != '#'){		
				load_url(line,re,root,type);
			}
		}
	}
	pcre_free(re);
        fclose(fp);
}
