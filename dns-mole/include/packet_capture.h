#include <pcap.h>
#include <net/ethernet.h>

#define PCAP_ROOT_ERROR -1
#define PCAP_LOOKUPDEV_ERROR -2
#define PCAP_OPEN_LIVE_ERROR -3
#define PCAP_COMPILE_ERROR -4
#define PCAP_SETFILTER_ERROR -5

struct ip_header {
	u_int8_t ip_ihl:4;
	u_int8_t ip_version:4;
	u_int8_t ip_tos;
	u_int16_t ip_length;
	u_int16_t ip_id;
	u_int16_t ip_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_int8_t ip_ttl;
	u_int8_t ip_proto;
	u_int16_t ip_checksum;
	u_int32_t ip_src;
	u_int32_t ip_dst;
};

struct udp_header {
	u_int16_t uh_srcport;
	u_int16_t uh_dstport;
	u_int16_t uh_length;
	u_int16_t uh_checksum;
};

struct dns_query_header {
	u_int16_t dq_id;
	u_int16_t dq_flags;
#define DQH_QR(dq) (((dq)->dq_flags & 0x8000) >> 15)
	u_int16_t dq_qc;
	u_int16_t dq_ac;
	u_int16_t dq_nc;
	u_int16_t dq_arc;
};

void pcap_callback(u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* handle ethernet packet */
u_int16_t ethernet_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* handle dns query packet */
void dns_query_handler (u_char * args, const struct pcap_pkthdr * pkthdr,
		const u_char * packet);

/* exam the validation of udp packet */
int validate_udp(u_int32_t * packet);

int packet_capture_loop ();
