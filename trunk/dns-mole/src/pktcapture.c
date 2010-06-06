#include "../include/pktcapture.h"
#include "../include/error.h"
#include <time.h>

int packet_capture_loop(int count) {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid()) {
		return PCAP_ROOT_ERROR;
	}

	/* look up device */
	dev = pcap_lookupdev(errbuf);
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

// just test ..
void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	uint16 type = get_ethernet_type(args, pkthdr, packet);
	switch (type) {
	case ETHERTYPE_IP:
		ip_handler(args, pkthdr, packet);
		break;
	default:break;
	};
}

uint16 get_ethernet_type (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	uint32 length = pkthdr->len;
	struct ether_header * ehdr;
	uint16 ether_type;
	ehdr = (struct ether_header *) packet;
	ether_type = ntohs(ehdr->ether_type);
	return ether_type;
}

void ip_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet) {
	query * q = (query *)malloc(sizeof(query));
	parse_to_query(pkthdr, q);
	qlist_insert(q);
}

int validate_iphdr(struct ip_header * ih) {

}

int validate_udp(uchar * packet) {

}

int validate_tcp(uchar * packet) {

}

void parse_to_query(uchar * packet, struct Query * q_store) {
	struct ip_header * ih = (struct ip_header *) (packet
				+ sizeof(struct ether_header));
	struct dns_query_header * dqh;
	if (ih->ip_proto == IP_PROTOCOL_TCP) {
		dqh = (struct dns_query_header *)(packet
				+ sizeof(struct ether_header) + ih->ip_ihl * 4 + sizeof(struct tcp_header));
	}
	else if (ih->ip_proto == IP_PROTOCOL_UDP) {
		dqh = (struct dns_query_header *)(packet
					+ sizeof(struct ether_header) + ih->ip_ihl * 4 + sizeof(struct udp_header));
	}
	q_store->q_srcip = ih->ip_src;
	q_store->q_time = time(NULL);


/*
 * Resource Record format
 * 0                16                32
 * +--------+--------+--------+--------+
 * |                                   |
 * ~               NAME                ~
 * |                                   |
 * +--------+--------+--------+--------+
 * |      TYPE       |      CLASS      |
 * +--------+--------+--------+--------+
 * |                TTL                |
 * +--------+--------+--------+--------+
 * | DATA LENGTH     |                 |
 * +-----------------+                 +
 * |                                   |
 * ~             DATA                  ~
 * |                                   |
 * +-----------------------------------+
 */
	char * dname = (char *)(packet	+ ih->ip_ihl * 4 + sizeof(struct udp_header)
				+ sizeof(struct ether_header) + sizeof(struct dns_query_header));
	dname += ntohs(dqh->dq_qc);
	char name[MAX_LENGTH];
	int i = 0;
	char t;
	for (; (*dname) != 0; dname++) {
		t = (*dname);
		if ((t >= 'a' && t <= 'z') || (t >= 'A' && t <= 'Z')
				|| (t >= '0' && t <= '9') || (t == '-')) {
			name[i++] = t;
		}
		else name[i++] = '.';
	}
	name[i] = '\0';
	strcpy(q_store->q_dname, name);

	if (i % 4 != 0)
		dname += 4 - (i % 4);

	q_store->q_type = ntohs(*((uint16 *)dname));

	dname += 4;
	q_store->q_ttl = ntohl(*((uint32 *)dname));

	dname += 4;
	uint16 dlen = ntohs(*((uint16 *)dname));

	q_store->q_value = (char *)malloc(dlen);
	strcpy(q_store->q_value, dname + 2);
}
