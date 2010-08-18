/* dnsmole.c
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <event.h>
#include <signal.h>

#include "../include/dnsmole.h"

moleWorld mWorld;
configuration *config;

void usage(char *pname,const int exit_val){
	fprintf(stdout,"\n\nUsage: %s "
	"-b <file>\t :blacklist file\n"
	"\t\t -w <file>\t :whitelist file\n"
	"\t\t -c <file>\t :config file\n"
	"\t\t -l <file>\t :log file\n"
	"\t\t -i <interface>\t :set interface\n"
	"\t\t -d\t\t :daemonize\n"
	"\t\t -s\t\t :sniffer mode\n"
	"\t\t -p <file>\t :read pcap file\n" 
	"\t\t -a <interval>\t :duration of .pcap package dump\n"
	"\t\t -h\t\t :display this usage screen\n"
	"\t\t -t <1|2|3>\t :detection method\n\n"
	"\t\t\t\t - 1 - Detection based on DNS query co-occurrence relation\n"
	"\t\t\t\t - 2 - Detection by monitoring group activities\n"
	"\t\t\t\t - 3 - Detection based on frequent host selection\n\n", pname);

	exit(exit_val);
}

void cleanup(){

    if(mWorld.p)
        pcap_close(mWorld.p);
    close_log(&mWorld);
}

void handler(int sig){
    if(sig == SIGILL || sig == SIGTERM){
        fflush(mWorld.log_fp);
        fflush(stderr); fflush(stdout);
        if(mWorld.p)
            pcap_close(mWorld.p);
        
        close_log(mWorld.log_fp);
        exit(EXIT_SUCCESS);
    }

    exit(EXIT_FAILURE);
    
}


void set_signal(int signal) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    
    if(sigaction(signal, &sa, NULL) < 0){
        fprintf(stderr,"[signal] Error\n"); exit(EXIT_FAILURE);
    }
}

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

void set_config(){
    configuration *t_config;
    
    config = create_t_configuration("aAnalyzeInterval",&mWorld.parameters.a_analyze_interval,0);
    register_config(config,"aDrop",(void *) &mWorld.parameters.activity_drop,0);
    register_config(config,"aBlackSimilarity",(void *) &mWorld.parameters.activity_bl_similarity,1);
    register_config(config,"aWhiteSimilarity",(void *) &mWorld.parameters.activity_wl_similarity,1);
    register_config(config,"oBlackIpTreshold",(void *) &mWorld.parameters.black_ip_treshold,1);
    register_config(config,"oWhite",(void *) &mWorld.parameters.o_white,1);
    register_config(config,"oBlack",(void *) &mWorld.parameters.o_black,1);
    register_config(config,"oAnalyzeInterval",(void *) &mWorld.parameters.o_analyze_interval,0);
    register_config(config,"nSubnet",(void *) &mWorld.parameters.subnet,0);
    register_config(config,"sThresholdTotal",(void *) &mWorld.parameters.s_threshold_total,1);
    register_config(config,"sThresholdPTR",(void *) &mWorld.parameters.s_threshold_ptr,1);
    register_config(config,"sThresholdMX",(void *) &mWorld.parameters.s_threshold_mx,1);
    register_config(config,"sThresholdBalance",(void *) &mWorld.parameters.s_threshold_balance,1);
    register_config(config,"sThresholdPTRRate",(void *) &mWorld.parameters.s_threshold_ptr_rate,1);
    register_config(config,"sThresholdMXRate",(void *) &mWorld.parameters.s_threshold_mx_rate,1);
    register_config(config,"sClassifyInterval",(void *) &mWorld.parameters.s_classify_interval,0);
    register_config(config,"sAnalyzeInterval",(void *) &mWorld.parameters.s_analyze_interval,0);
}
            
void read_config(const char *conf){ 
    FILE *config_file;
    configuration *t_config;
    char line[80],config_variable[80],number_variable[10];
    int first,second,count,variable_count,number_count,line_count = 0;
    int done, *t_int;
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
                        number_variable[number_count] = line[count];
                        number_count++;
                        if(line[count + 1] == ' ' || line[count + 1] == '\n'){
                            second = 0;
                        }
                    }
                }

                config_variable[variable_count] = '\0';
                number_variable[number_count] = '\0';

                if(!first && !second){

                    t_config = config;
                    while(t_config && !done){
                        if(!strcmp(t_config->variable,config_variable)){
                            if(t_config->type == 1){
                                t_float = (float *)t_config->where;
                                *t_float = atof(number_variable);
                            }
                            else if(t_config->type == 0){
                                t_int = (int *)t_config->where;
                                *t_int = atoi(number_variable);
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

int read_pcap(const char *p_file){

    mWorld.qlist_head = mWorld.qlist_rear = 0;
    mWorld.count = 0;
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    if(access(p_file,F_OK)){
        fprintf(stderr,"Error opening %s (is the path correct ? )\n",p_file);
        return -1;
    }
    else{   
        if((handler = pcap_open_offline(p_file,errbuf)) == NULL){
            fprintf(stderr,"[pcap_open_offline] Error\n");
            return -1;
        }
        
        mWorld.dl_len = pcap_dloff(handler);

        if(pcap_compile(handler,&filter,DNS_QUERY_FILTER,0,0) == -1)
            return PCAP_COMPILE_ERROR;

        if(pcap_setfilter(handler,&filter) == -1)
            return PCAP_SETFILTER_ERROR;
    
        if(pcap_dispatch(handler,0,(void *) pcap_callback, (void *) &mWorld) < 0){
            fprintf(stderr,"[pcap_dispatch] Error\n"); return -1;
        }

        pcap_close(handler);
    }
    return 1;

}

int main(int argc,char **argv){
    char option;
    char *blacklist_file = NULL;
    char *whitelist_file = NULL;
    char *logfile = NULL;
    char *interface = NULL;
    char *config = NULL;
    char *pcap_file = NULL;
    int daemonize = 0, sniffer = 0;
    kdomain *temp_domain;

    set_signal(SIGHUP);
    set_signal(SIGINT);
    set_signal(SIGILL);
    set_signal(SIGQUIT);
    //set_signal(SIGSEGV);
    set_signal(SIGTERM);
    
    while((option = getopt(argc,argv,"i:b:w:t:l:c:dsp:a:h?")) > 0){
	switch(option){
	    case 'b':
		blacklist_file = optarg;
		break;

	    case 'w':
		whitelist_file = optarg;
		break;

	    case 'l':
		logfile = optarg;
		break;
	
	    case 'c':
		config = optarg;
		break;
            
	    case 't':
		mWorld.type = atoi(optarg);
		break;

	    case 'd':
		daemonize = 1;
		break;

	    case 's':
		sniffer = 1;
		break;

	    case 'p':
		pcap_file = optarg;
		break;
            	
	    case 'a':
		mWorld.parameters.pcap_interval = atoi(optarg);
		break;
        
	    case 'i':
		interface = optarg;
		break;

	    case '?':
	    case 'h':
	    	usage(argv[0],EXIT_SUCCESS);

	    default:
		break;
	    }
	}
    
    argc -= optind;
    argv += optind;

    if(daemonize)
        daemon(1,0);
    
    mWorld.root_list = new_domain_structure("ROOT",-1);

    if(mWorld.type == 0){
	    fprintf(stderr,"\n[*] Please choose detection method [ -t ])\n");
        exit(EXIT_FAILURE);
    }

    if(((interface == NULL) && sniffer) && (pcap_file == NULL)){
        fprintf(stderr,"\n[*] Please set interface for sniffer or provide .pcap file for analysis\n");
        exit(EXIT_FAILURE);
    }

    if(!(pcap_file == NULL) && !mWorld.parameters.pcap_interval && mWorld.type == 2){
        fprintf(stderr,"\n[*] Please set pcap file dump interval for method 2 [ -a ]\n");
        exit(EXIT_FAILURE);
    }

    if(!config){
        fprintf(stderr,"\n[*] Please set config file [ -c ]\n");
        exit(EXIT_FAILURE);
    }

    set_config();
    read_config(config);

    if(interface){
        if(!(mWorld.interface = (char *) malloc(sizeof(char) * strlen(interface)))){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        memcpy(mWorld.interface,interface,strlen(interface)+1);
    }
    
    if(!logfile){
        open_log(&mWorld,"dnsmole-log"); 
    }
    else 
        open_log(&mWorld,logfile); 
    
    if(blacklist_file) //&&  (mWorld.type != 3))
	    read_list(mWorld.root_list,blacklist_file,1);
        
    if(whitelist_file) //&& (mWorld.type != 3))
	    read_list(mWorld.root_list,whitelist_file,0);

    if(!mWorld.parameters.subnet)
        mWorld.parameters.subnet = 16;
   
    if(pcap_file){
        if(read_pcap(pcap_file)){
            switch(mWorld.type){
                case 1:
                    populate_store_structure(mWorld.count,(void *) &mWorld,1);
                    break;
                case 2:
                    populate_store_structure(mWorld.count,(void *) &mWorld,2);
                    break;
                case 3:
                    statistics_method(mWorld.count,(void *) &mWorld);
                    break;
            }
        }
    }

    pcap_file = NULL;
    mWorld.parameters.pcap_interval = 0;
   
    if(sniffer && interface){
        
	event_init();
        
        if(sniffer_setup((void *)&mWorld) < 0){
	        fprintf(stderr,"[sniffer_setup] error\n");
	        exit(EXIT_FAILURE);
	    }
    
        mWorld.tv.tv_sec = 0;
        mWorld.tv.tv_usec = 500;

        switch(mWorld.type){
            case 1:
                mWorld.analyze_tv.tv_sec = mWorld.parameters.a_analyze_interval;
                break;
            case 2:
                mWorld.analyze_tv.tv_sec = mWorld.parameters.o_analyze_interval;
                break;
            case 3:
                mWorld.analyze_tv.tv_sec = mWorld.parameters.s_analyze_interval;
                break;
        }

        if(!mWorld.analyze_tv.tv_sec) 
            mWorld.analyze_tv.tv_sec = 600;

        mWorld.analyze_tv.tv_usec = 0;
        
        mWorld.pcap_fd = pcap_fileno(mWorld.p);

        event_set(&mWorld.recv_ev,mWorld.pcap_fd,EV_READ, _dns_sniffer, (void *)&mWorld);
        event_add(&mWorld.recv_ev, NULL);

        evtimer_set(&mWorld.analyze_ev, _analyzer, (void *)&mWorld);
        evtimer_add(&mWorld.analyze_ev,&mWorld.analyze_tv);
        
        event_dispatch();

    }

    cleanup();
	
    fprintf(stdout,"... remember when you were young ... \n");
    exit(EXIT_SUCCESS);
}
