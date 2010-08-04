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

#include "../include/knowndomain.h"
#include "../include/dnsmole.h"

void usage(char *pname,const int exit_val){
	fprintf(stdout,"\n\nUsage: %s "
		   "\t -b <filename>\t :blacklist filename\n"
		   "\t\t -w <filename>\t :whitelist filename\n"
		   "\t\t -l <filename>\t :log file\n"
                   "\t\t -i <interface>\t : set interface\n"
                   "\t\t -r <timeout>\t : set timeout\n"
		   "\t\t -t <0|1>\n"
		   "\t\t\t\t 1 - Anomaly detection using entropy\n"
		   "\t\t\t\t 2 - Wavelet analysis\n\n"
		   "\t\t -d\t\t :daemonize\n"
		   "\t\t -s\t\t :sniffer mode\n"
		   "\t\t -h\t\t :display this usage screen\n\n", pname);

	exit(exit_val);
}

int main(int argc,char **argv){
    char option;
    char *blacklist_file = NULL;
    char *whitelist_file = NULL;
    char *logfile = NULL;
    char *interface = NULL;
    int daemonize = 0, sniffer = 0, timeout = 10;
    moleWorld mWorld;

    while((option = getopt(argc,argv,"i:b:w:t:l:r:dsh?")) > 0){
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
	
	    case 'r':
		timeout = atoi(optarg);
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

    mWorld.re = initialize_regex();
    mWorld.root_list = new_domain_structure("ROOT");
    mWorld.bad_ip = NULL;

    if(mWorld.type == 0)
	fprintf(stderr,"\n[*] Using BlackList Comprasion (Please choose detection mode [ -t ])\n");

    if(!interface){
        fprintf(stderr,"\n[*] Please set interface [ -i <interface> ]\n");
        exit(EXIT_FAILURE);
    }
    
    if(!(mWorld.interface = (char *) malloc(sizeof(char) * strlen(interface)))){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
    }

    memcpy(mWorld.interface,interface,strlen(interface)+1);
    

    if(blacklist_file)
	read_list(mWorld.root_list,blacklist_file,1,mWorld.re);
        
    if(whitelist_file)
	read_list(mWorld.root_list,whitelist_file,0,mWorld.re);
    
    if(!logfile){
        open_log(mWorld.log_fp,"mole_log");
    }
    else{ 
        open_log(mWorld.log_fp,logfile);     
    }

    if(sniffer){
        event_init();
        
        if(sniffer_setup((void *)&mWorld) < 0){
	    fprintf(stderr,"[sniffer_setup] error\n");
	    exit(EXIT_FAILURE);
	}
    
        mWorld.tv.tv_sec = 0;
        mWorld.tv.tv_usec = 500;

        mWorld.analyze_tv.tv_sec = timeout;
        mWorld.analyze_tv.tv_usec = 0;

        mWorld.learn_tv.tv_sec = timeout*5;
        mWorld.learn_tv.tv_usec = 0;
        
        mWorld.pcap_fd = pcap_fileno(mWorld.p);
        event_set(&mWorld.recv_ev,mWorld.pcap_fd,EV_READ, _dns_sniffer, (void *)&mWorld);
        event_add(&mWorld.recv_ev, NULL);

        evtimer_set(&mWorld.learn_ev, _learn,(void *)&mWorld);
        evtimer_add(&mWorld.learn_ev,&mWorld.learn_tv);
    
        evtimer_set(&mWorld.analyze_ev, _analyzer, (void *)&mWorld);

        event_dispatch();
    }
    
    
    if(sniffer)
	pcap_close(mWorld.p); 
		
    pcre_free(mWorld.re);
    close_log(mWorld.log_fp);
	
    fprintf(stdout,"... remember when you were young ... \n");
    exit(EXIT_SUCCESS);
}
