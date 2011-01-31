/* config.c
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
 
 configuration *create_t_configuration(const char *name, void *where,int type){
    configuration *t_config;
    
    if((t_config = (configuration *) malloc(sizeof(configuration))) != NULL){
        if((t_config->variable = malloc(strlen(name) * sizeof(char) + 1)) != NULL){
            memcpy(t_config->variable,name,strlen(name)+1);
            t_config->where = where;
            t_config->type = type;
            t_config->next = NULL;
            return t_config;
        }
    }
    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
}

void register_config(configuration *begin,const char *name,void *where,int type){
    configuration *loop_config;

    loop_config = begin;
    while(loop_config->next)
        loop_config = loop_config->next;

    loop_config->next = create_t_configuration(name,where,type);;
}

configuration *set_config(void *confMole){
    
    moleWorld *configMole = (moleWorld *) confMole;
    configuration *config;

    config = create_t_configuration("aAnalyzeInterval",(void *)&(configMole->parameters).a_analyze_interval,0);
    register_config(config,"aDrop",(void *)&(configMole->parameters).activity_drop,0);
    register_config(config,"aBlackSimilarity",(void *)&(configMole->parameters).activity_bl_similarity,1);
    register_config(config,"aWhiteSimilarity",(void *)&(configMole->parameters).activity_wl_similarity,1);
    register_config(config,"oBlackIpTreshold",(void *)&(configMole->parameters).black_ip_treshold,1);
    register_config(config,"oWhite",(void *)&(configMole->parameters).o_white,1);
    register_config(config,"oBlack",(void *)&(configMole->parameters).o_black,1);
    register_config(config,"oAnalyzeInterval",(void *)&(configMole->parameters).o_analyze_interval,0);
    register_config(config,"nSubnet",(void *)&(configMole->parameters).subnet,0);
    register_config(config,"sThresholdTotal",(void *)&(configMole->parameters).s_threshold_total,1);
    register_config(config,"sThresholdPTR",(void *)&(configMole->parameters).s_threshold_ptr,1);
    register_config(config,"sThresholdMX",(void *)&(configMole->parameters).s_threshold_mx,1);
    register_config(config,"sThresholdBalance",(void *)&(configMole->parameters).s_threshold_balance,1);
    register_config(config,"sThresholdPTRRate",(void *)&(configMole->parameters).s_threshold_ptr_rate,1);
    register_config(config,"sThresholdMXRate",(void *)&(configMole->parameters).s_threshold_mx_rate,1);
    register_config(config,"sClassifyInterval",(void *)&(configMole->parameters).s_classify_interval,0);
    register_config(config,"sAnalyzeInterval",(void *)&(configMole->parameters).s_analyze_interval,0);
    register_config(config,"LogFile",(void *)&(configMole->log_file),2);
    register_config(config,"nAnalyzeInterval",(void *)&(configMole->parameters).naive_analyze_interval,0);

    return config;
}
            
void read_config(const char *conf,configuration *config){ 
    FILE *config_file;
    configuration *t_config;
    char line[80],config_variable[30],variable[50];
    int first,second,count,variable_count,number_count,line_count = 0;
    int done, *t_int;
    char **t_str;
    float *t_float;
    
    if((config_file = fopen(conf,"r")) != NULL){
        while(fgets(line,sizeof(line),config_file) != NULL){
            line_count++;
            variable_count = number_count = second = done = 0;
            first = 1;
            if((isalpha(line[0]) || isdigit(line[0]))){
                for(count = 0; count < strlen(line); count++){
                    if(first && line[count] != ' '){
                        config_variable[variable_count] = line[count];
                        variable_count++;
                        if(line[count + 1] == ' '){
                            first = 0; second = 1;
                        }
                    }
                    else if(second && line[count] != ' '){
                        variable[number_count] = line[count];
                        number_count++;
                        if(line[count + 1] == ' ' || line[count + 1] == '\n'){
                            second = 0;
                        }
                    }
                }

                config_variable[variable_count] = '\0';
                variable[number_count] = '\0';

                if(!first && !second){
                    t_config = config;
                    while(t_config && !done){
                        if(!strcmp(t_config->variable,config_variable)){
                            if(t_config->type == 0){
                                t_int = (int *)t_config->where;
                                *t_int = atoi(variable);
                            }
                            
                            else if(t_config->type == 1){
                                t_float = (float *)t_config->where;
                                *t_float = atof(variable);
                            }

                            else if(t_config->type == 2){
                                t_str = (char **)t_config->where;
                                if((*t_str = (char *) malloc(strlen(variable)*sizeof(char) + 1)) == NULL){
				    fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
				}
                                memcpy(*t_str,variable,strlen(variable)+1);
                            }

                            done = 1;
                            
                        }
                        t_config = t_config->next;
    
                    }

                    if(!done){
                        fprintf(stderr,"Error in reading configuration (line: %i), what is %s ?\n",line_count,config_variable);
                        exit(EXIT_FAILURE);
                    }
                }
                else{
                    fprintf(stderr,"Error in configuration file, line %i\n",line_count);
                    exit(EXIT_FAILURE);
                }
            }
            
        }
    }
}
