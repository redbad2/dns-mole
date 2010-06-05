#ifndef DNSM_DOMAIN_H
#define DNSM_DOMAIN_H

#define MAX_DN_LENGTH 256

struct KnownDomain{
	char d_domain_name[MAX_DN_LENGTH];
	int d_reput;
	unsigned int d_ip;
};

#endif /* DNSM_DOMAIN_H */
