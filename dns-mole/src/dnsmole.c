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
		   "\t\t -o <filename>\t :log file\n"
                   "\t\t -i <interface>\t : set interface\n"
                   "\t\t -r <timeout>\t: set timeout\n"
		   "\t\t -t <0|1>\n"
		   "\t\t\t\t 0 - Anomaly detection using entropy\n"
		   "\t\t\t\t 1 - Wavelet analysis\n\n"
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
    int type = 0 , daemonize = 0, sniffer = 0, timeout = 10;
    moleWorld mWorld;

	while((option = getopt(argc,argv,"b:w:t:l:o:dsh?")) > 0){
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

    //set_signal_handler();
    mWorld.root_list = new_domain_structure("ROOT");

    if(!type)
	fprintf(stderr,"\n[*] Please choose detection mode [ -t ]\n");

    if(!interface)
        fprintf(stderr,"\n[*] Please set interface [ -i <interface> ]\n");
    
    if(!(mWorld.interface = (char *) malloc(sizeof(char) * strlen(interface)))){
            fprintf(stderr,"[malloc] OOM\n"); exit(EXIT_FAILURE);
    }

    memcpy(mWorld.interface,interface,strlen(interface));

    if(blacklist_file)
	read_list(mWorld.root_list,blacklist_file,1);
        
    if(whitelist_file)
	read_list(mWorld.root_list,whitelist_file,0);
    
    if(!logfile)
        open_log(mWorld.log_fp,"mole_log"); 
    else 
        open_log(mWorld.log_fp,logfile);     

	if(sniffer)
		if(sniffer_setup(&mWorld, 0) < 0)
			exit(EXIT_FAILURE);
    //mWorld.pcap = pcap_openlive(interface,1500,1,500,ebuff);
    
    event_init();
    
    mWorld.tv.tv_set = 0;
    mWorld.tv.tv_usec = 500;

    mWorld.analyze_tv.tv_set = timeout;
    mWorld.analyze_tv.tv_usec = 0;

    mWorld.learn_tv.tv_set = timeout*10;
    mWorld.learn_tv.tv_usec = 0;

    event_set(&mWorld.recv_ev, p_fd, _dns_sniffer, (void *)&mWorld);
    event_add(&mWorld.recv_ev, NULL);

    evtimer_set(&mWorld.learn_ev, _learn,(void *)&mWorld);
    evtimer_add(&mWorld.learn_ev,&mWorld.learn_tv);
    
    evtimer_set(&mWorld.analyze_ev, _analyzer, (void *)&mWorld);

    event_dispatch();

    //cleanup();
    exit(EXIT_SUCCESS);
}
