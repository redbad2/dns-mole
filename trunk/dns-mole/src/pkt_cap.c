#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include "../include/pkt_cap.h"
#include "../include/error.h"
#include "../include/dns_parser.h"



int main(int argc, char ** argv) {
	int r;
	qlist_init();
	if ((r = packet_capture_loop(NULL, 100)) < 0) {
		printf("pkt error %d", r);
		return 0;
	}

	qentry * q = qlist.head;
	FILE * file = fopen("log.txt", "w");
	while(q != NULL) {
		fprintf(file, "DNAME: %s\n", q->qe_qry->q_dname);
		fprintf(file, "\tIP: %s\n", (char *)inet_ntoa(q->qe_qry->q_srcip));
		fprintf(file, "\tTIME: %d\n", (int)q->qe_qry->q_time);
		fprintf(file, "\tTTL: %d\n", q->qe_qry->q_ttl);
		fprintf(file, "\tTYPE: %d\n", q->qe_qry->q_type);
		fprintf(file, "\tVALUE: %s\n", q->qe_qry->q_value);

		q = q->qe_next;
	}
	printf("packet capture finished\n");
	fclose(file);

	q = qlist.head;
	qentry * p;
	while(q != NULL) {
		p = q->qe_next;
		qlist_remove(q);
		q = p;
	}
	return 0;
}


/*
 * main packet capture loop
 */
int packet_capture_loop(char * interface, int count) {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid()) {
		return PCAP_ROOT_ERROR;
	}

	/* look up device */
	if (interface == NULL) {
		dev = pcap_lookupdev(errbuf);
	}
	else dev = interface;
	if (dev == NULL) {
		return PCAP_LOOKUPDEV_ERROR;
	}

	/* ask pcap for the network address and mask of the device */
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* open device for reading */
	pcap_t * descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (descr == NULL) {
		return PCAP_OPEN_LIVE_ERROR;
	}

	/* compile the program */
	struct bpf_program filter;
	if (pcap_compile(descr, &filter, DNS_QUERY_FILTER, 0, netp) == -1) {
		return PCAP_COMPILE_ERROR;
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(descr, &filter) == -1) {
		return PCAP_SETFILTER_ERROR;
	}

	/* loop */
	pcap_loop(descr, count, pcap_callback, NULL);

	return 0;
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
	query * q = (query *)malloc(sizeof(query));
	memset(q, 0, sizeof(query));
	dns2query((u_char *)packet, pkthdr->len, q);
	q->q_time = pkthdr->ts.tv_sec;
	qlist_append(q);
}

