#include "packet_capture.h"

int packet_capture_loop() {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid()) {
		//printf("should be executed as root.\n");
		return PCAP_ROOT_ERROR;
	}

	/* look up device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		//printf("pcap_lookupdev error: %s\n", errbuf);
		return PCAP_LOOKUPDEV_ERROR;
	}

	/* ask pcap for the network address and mask of the device */
	bpf_u_int32 maskp;
	bpf_u_int32 netp;
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* open device for reading */
	pcap_t * descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (descr == NULL) {
		//printf("pcap_open_live error: %s\n", errbuf);
		return PCAP_OPEN_LIVE_ERROR;
	}

	/* compile the program */
	struct bpf_program filter;
	char dns_query_filter[]= "udp port 53";
	if (pcap_compile(descr, &filter, dns_query_filter, 0, netp) == -1) {
		//printf("pcap_compile error\n");
		return PCAP_COMPILE_ERROR;
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(descr, &filter) == -1) {
		//printf("pcap_setfilter error\n");
		return PCAP_SETFILTER_ERROR;
	}

	/* loop */
	pcap_loop(descr, -1, pcap_callback, NULL);

	return 0;
}

// just test ..
void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	u_int16_t type = ethernet_handler(args, pkthdr, packet);
	switch (type) {
	case ETHERTYPE_IP:
		dns_query_handler(args, pkthdr, packet);
		break;
	default:break;
	};
}

u_int16_t ethernet_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	u_int length = pkthdr->len;
	struct ether_header * ehdr;
	u_short ether_type;
	ehdr = (struct ether_header *) packet;
	ether_type = ntohs(ehdr->ether_type);

	/* do something */
	fprintf(stdout,"eth: ");
	fprintf(stdout, "%s ",ether_ntoa((struct ether_addr*)ehdr->ether_shost));
	fprintf(stdout, "%s ",ether_ntoa((struct ether_addr*)ehdr->ether_dhost));
	fprintf(stdout, "%d\n", length);

	return ether_type;
}

void dns_query_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	struct ip_header * ih = (struct ip_header *) (packet
			+ sizeof(struct ether_header));
	fprintf(stdout, "ip header:\nver %d ihl %d tos %d length %d\n", ih->ip_version,
			ih->ip_ihl, ih->ip_tos, ih->ip_length);
	fprintf(stdout, "id %d off %d ttl %d proto %d\n", ih->ip_id, ih->ip_off,
			ih->ip_ttl, ih->ip_proto);
	fprintf(stdout, "checksum %d ", ih->ip_checksum);
	fprintf(stdout, "src_ip %s -> ", inet_ntoa(ih->ip_src));
	fprintf(stdout, "dst_ip %s\n", inet_ntoa(ih->ip_dst));


	struct udp_header * uh = (struct udp_header *)(packet
			+ sizeof(struct ether_header) + ih->ip_ihl * 4);
	fprintf(stdout, "udp header:\nsrc_port %d dst_port %d\n", ntohs(uh->uh_srcport),
			ntohs(uh->uh_dstport));
	fprintf(stdout, "length %d checksum %d\n", uh->uh_length, uh->uh_checksum);



struct dns_query_header * dqh = (struct dns_query_header *)(packet
		+ sizeof(struct ether_header) + ih->ip_ihl * 4 + sizeof(struct udp_header));
	fprintf(stdout, "dqh:\nid %d qr %d qc %d ac %d nc %d arc %d\n", dqh->dq_id,
			DQH_QR(dqh), dqh->dq_qc, dqh->dq_ac, dqh->dq_nc, dqh->dq_arc);


	char * dn = (char *)(packet	+ ih->ip_ihl * 4 + sizeof(struct udp_header)
			+ sizeof(struct ether_header) + sizeof(struct dns_query_header));
	fprintf(stdout, "dn: %s\n", dn);

	return;
}
