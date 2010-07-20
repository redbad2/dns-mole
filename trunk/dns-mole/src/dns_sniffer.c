#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include "../include/dns_sniffer.h"
#include "../include/error.h"
#include "../include/dns_parser.h"


int sniffer_setup(moleWorld * mWorld) {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid()) {
		return PCAP_ROOT_ERROR;
	}

	/* look up device */
	if (mWorld->interface == NULL) {
		dev = pcap_lookupdev(errbuf);
	}
	else dev = mWorld->interface;
	if (dev == NULL) {
		return PCAP_LOOKUPDEV_ERROR;
	}

	/* ask pcap for the network address and mask of the device */
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* open device for reading */
	mWorld->p = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (mWorld->p == NULL) {
		return PCAP_OPEN_LIVE_ERROR;
	}

	/* compile the program */
	struct bpf_program filter;
	if (pcap_compile(mWorld->p, &filter, DNS_QUERY_FILTER, 0, netp) == -1) {
		return PCAP_COMPILE_ERROR;
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(mWorld->p, &filter) == -1) {
		return PCAP_SETFILTER_ERROR;
	}
	
	return 0;
}


int _dns_sniffer(int fd, short event, void *arg) {
    int r;
    struct moleWorld *myMole= (struct moleWorld *) arg;

    evtimer_add(&myMole->recv_ev, &myMole->recv_tv);
    
    r = pcap_dispatch(myMole->p, 0, pcap_callback, myMole);
    return r;
}


/*
 * handle every packet captured
 */
void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	unsigned short type = get_ethernet_type(args, pkthdr, packet);
	switch (type) {
	case ETHERTYPE_IP:
		ip_handler(args, pkthdr, packet);
		break;
	default:break;
	};
}

/*
 * get type of ethernet packet, e.g. IP, ARP
 */
unsigned short get_ethernet_type (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	unsigned int length = pkthdr->len;
	struct ether_header * ehdr;
	unsigned short ether_type;
	ehdr = (struct ether_header *) packet;
	ether_type = ntohs(ehdr->ether_type);
	return ether_type;
}

/*
 * parse ip packet to query
 */
void ip_handler (u_char * args, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	struct moleWorld * mWorld = (struct moleWorld *) args;
	query * q = (query *)malloc(sizeof(query));
	memset(q, 0, sizeof(query));
	dns2query((u_char *)packet, pkthdr->len, q);
	q->q_time = pkthdr->ts.tv_sec;
	qlist_append(mWorld->query_list, q);
}

