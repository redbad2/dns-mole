#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/types.h"
#include "../include/knowndomain.h"

#define VERSION 0.1

void usage(char *pname,const int exit_val){
	fprintf(stdout,"\n\nUsage: %s "
		   "\t -b <filename>\t :blacklist filename\n"
		   "\t\t -w <filename>\t :whitelist filename\n"
		   "\t\t -l <filename>\t :using bind log for analyzing\n"
		   "\t\t -o <filename>\t :db output file\n"
		   "\t\t -t <0|1>\n"
		   "\t\t\t\t 0 - blacklist comparsion\n"
		   "\t\t\t\t 1 - Anomaly detection using entropy\n\n"
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
	char *dboutput = NULL;
	int32 type = 0 , daemonize = 0, sniffer = 0;
        kdomain *root_list = new_domain_structure("ROOT");

	while((option = getopt(argc,argv,"b:w:t:l:o:dsh?")) > 0){
		switch(option){
			case 'b':
				blacklist_file = optarg;
				break;

			case 'w':
				whitelist_file = optarg;
				break;

			case 'o':
				dboutput = optarg;
				break;

			case 'l':
				logfile = optarg;
				break;

			case 't':
				type = atoi(optarg);
				break;

			case 'd':
				daemonize = 1;
				break;

			case 's':
				sniffer = 1;
				break;

			case '?':
			case 'h':
				usage(argv[0],EXIT_SUCCESS);

			default:
				break;
		}
	}
	if(sniffer && logfile){
		fprintf(stderr,"\n[*] Please select either log analysis OR sniffer mode [ -s OR -l <filename>]\n");
		usage(argv[0],EXIT_FAILURE);
	}
	if(!type){
		fprintf(stderr,"\n[*] Please choose detection mode [ -t ]\n");
		usage(argv[0],EXIT_FAILURE);
	}
	if(blacklist_file)
    	        read_list(root_list,blacklist_file,1);
        
        if(whitelist_file)
                read_list(root_list,whitelist_file,0);
        
	
        return(EXIT_SUCCESS);
}
