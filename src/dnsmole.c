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

#include <signal.h>

#include "../include/dnsmole.h"

moleWorld mWorld;
configuration *config;

void usage(char *pname,const int exit_val){
	fprintf(stdout,"\nDNSMole - DNS traffic analyzer for detecting botnet activity\n");
    fprintf(stdout,"( http://code.google.com/p/dns-mole ) \n");
    fprintf(stdout,"\n\nUsage: %s "
	"-b <file>\t :blacklist file\n"
	"\t\t -w <file>\t :whitelist file\n"
	"\t\t -c <file>\t :config file\n"
	"\t\t -i <interface>\t :set interface\n"
	"\t\t -d\t\t :daemonize\n"
	"\t\t -s\t\t :sniffer mode\n"
	"\t\t -p <file>\t :read pcap file\n" 
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
        
    // closeDB(&mWorld);
    closeLog(&mWorld);
}

void handler(int sig){
	
    if(sig == SIGILL || sig == SIGTERM){
        fflush(mWorld.log_fp);
        fflush(stderr); fflush(stdout);
        
        if(mWorld.p)
            pcap_close(mWorld.p);
        
        closeLog(mWorld.log_fp);
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

int read_pcap(const char *p_file){

    mWorld.qlist_head = mWorld.qlist_rear = 0;
    mWorld.count = 0;
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    if(access(p_file,F_OK)){
        fprintf(stderr,"Error opening %s (is the path correct ? )\n",p_file);
        return -1;
    } else {   
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

void _analyzer(int fd,short event,void *arg){
	
    moleWorld *analyzeMole = (moleWorld *) arg;
    int num_packets = analyzeMole->count;
	
    if(num_packets != 0){
	analyzeMole->count = 0;
	(analyzeMole->moleFunctions).analyze(num_packets,(void *)analyzeMole);
	event_add(&analyzeMole->analyze_ev,&analyzeMole->analyze_tv);
    }
                    
}   

int main(int argc,char **argv){
	
    char option;
    char *blacklist_file = NULL;
    char *whitelist_file = NULL;
    char *file_config = NULL;
    char *interface = NULL;
    char *pcap_file = NULL;
    int daemonize = 0, sniffer = 0;

    set_signal(SIGHUP);
    set_signal(SIGINT);
    set_signal(SIGILL);
    set_signal(SIGQUIT);
    //set_signal(SIGSEGV);
    set_signal(SIGTERM);
    
	
    while((option = getopt(argc,argv,"i:b:w:t:c:dsp:h?")) > 0){
	switch(option){
			
	    case 'b':
	        blacklist_file = optarg;
		break;

	    case 'w':
		whitelist_file = optarg;
		break;

	    case 'c':
		file_config = optarg;
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
	fprintf(stderr,"\n\n[*] Please choose detection method [ -t ])\n\n");
        exit(EXIT_FAILURE);
    }
    
    if(((interface == NULL) && sniffer) && (pcap_file == NULL)){
        fprintf(stderr,"\n\n[*] Please set interface for sniffer or provide .pcap file for analysis\n\n");
        exit(EXIT_FAILURE);
    }

    if(!file_config){
        fprintf(stderr,"\n[*] Please set config file [ -c ]\n");
        exit(EXIT_FAILURE);
    }

    config = set_config((void *)&mWorld);
    read_config(file_config,config);

    switch(mWorld.type){
        case 1:
            cor_initialize((void *) &mWorld);
            break;
        case 2:
            ga_initialize((void *) &mWorld);
            break;
        case 3:
            naive_initialize((void *) &mWorld);
            break;
    }
    

    if(interface){
        if(!(mWorld.interface = (char *) malloc(sizeof(char) * strlen(interface)))){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
        }
        memcpy(mWorld.interface,interface,strlen(interface)+1);
    }
    
    if(!mWorld.log_file){
        openLog(&mWorld,"dnsmole-log"); 
    }
    else 
        openLog(&mWorld,mWorld.log_file); 
    
    if(blacklist_file)
	    read_list(mWorld.root_list,blacklist_file,1);
        
    if(whitelist_file)
	    read_list(mWorld.root_list,whitelist_file,0);

    if(!mWorld.parameters.subnet)
        mWorld.parameters.subnet = 16;
   
    if(pcap_file){
        if(read_pcap(pcap_file))
		mWorld.moleFunctions.analyze(mWorld.count,(void *) &mWorld);
        printf("\n\n[*] File: %s analyzed\n\n",pcap_file);
    }

    pcap_file = NULL;
   
    if(sniffer && interface){
        
    	event_init();
        
        if(sniffer_setup((void *)&mWorld) < 0){
	        fprintf(stderr,"[sniffer_setup] error\n");
	        exit(EXIT_FAILURE);
	    }
    
        mWorld.tv.tv_sec = 0;
        mWorld.tv.tv_usec = 500;

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
	
    exit(EXIT_SUCCESS);
}
