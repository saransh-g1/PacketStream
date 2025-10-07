#include "../vmlinux/vmlinux.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <XDP.hpp>

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = (struct ethhdr *)nh->pos;
    int hdrsize = sizeof(*eth);

    if( nh->pos+1 > data_end){
        return -1;
    }

    nh->pos = (void *)((int *)nh->pos + hdrsize);
    *ethhdr = eth;

    return eth->h_proto;

}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
    
    struct ipv6hdr *ip6h = (struct ipv6hdr*)nh->pos;
	int ipv6hdr_size = sizeof(*ip6h);
		if (ip6h + 1 > data_end)
		return -1;

	nh->pos = (void *)((int *)nh->pos + ipv6hdr_size);
    *ip6hdr = ip6h;
	
	return ip6h->;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{   
	struct icmp6hdr *icmp6h = (struct icmp6hdr*)nh->pos;
	int icmp6hdr_size = sizeof(*icmp6h);
		if (icmp6h+ 1 > data_end)
		return -1;

	nh->pos = (void *)((int *)nh->pos + icmp6hdr_size);
    *icmp6hdr = icmp6h;
	
	return icmp6h->icmp6_type;

}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iphdr)
{
	struct iphdr *iph = (struct iphdr*)nh->pos;
	int iphdr_size = sizeof(*iph);
		if (iph + 1 > data_end)
		return -1;

	nh->pos = (void *)((int *)nh->pos + iphdr_size);
    *iphdr = iph;
	
	return iph->;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmphdr)
{
	struct icmphdr *icmph = (struct icmphdr*)nh->pos;
	int icmphdr_size = sizeof(*icmph);
		if (icmph + 1 > data_end)
		return -1;

	nh->pos = (void *)((int *)nh->pos + icmphdr_size);
    *icmphdr = icmph;
	
	return icmph->type;
}
