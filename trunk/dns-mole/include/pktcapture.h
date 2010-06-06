#include <pcap.h>
#include <net/ethernet.h>
#include <types.h>

#define DNS_QUERY_FILTER "tcp or udp port 53"
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

struct ip_header {
	uchar ip_ihl:4;
	uchar ip_version:4;
	uchar ip_tos;
	uint16 ip_length;
	uint16 ip_id;
	uint16 ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	uchar ip_ttl;
	uchar ip_proto;
	uint16 ip_checksum;
	uint32 ip_src;
	uint32 ip_dst;
};

struct udp_header {
	uint16 uh_srcport;
	uint16 uh_dstport;
	uint16 uh_length;
	uint16 uh_checksum;
};

struct tcp_header {
	uint16 th_srcport;
	uint16 th_dstport;
	uint32 th_seq;
	uint32 th_ack;
	uint16 th_code;
#define TH_LEN(th) (((th)->th_code & 0xf000) >> 12)
	uint16 th_win;
	uint16 th_checksum;
	uint16 th_urgpt;
};

struct dns_query_header {
	uint16 dq_id;
	uint16 dq_flags;
#define DQH_QR(dq) (((dq)->dq_flags & 0x8000) >> 15)
	uint16 dq_qc;
	uint16 dq_ac;
	uint16 dq_nc;
	uint16 dq_arc;
};


/*
 * count = -1 for infinite loop
 * count = 0 for stop until error
 */
int packet_capture_loop (int count);

void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* handle ethernet packet */
uint16 get_ethernet_type (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

void ip_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);


/* examine the validation of udp packet */
int validate_iphdr(struct ip_header * ih);
int validate_udp(uchar * packet);
int validate_tcp(uchar * packet);

/* parse an ethernet packet to a query */
void parse_to_query(uchar * packet, struct Query * q_store);
