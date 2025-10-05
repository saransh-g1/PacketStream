#include "../vmlinux/vmlinux.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct hdr_cursor {
	void *pos;
};

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

SEC("xdp")

int xdp_parser_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    
    __u32 action = XDP_PASS;

    struct hdr_cursor nh;
    int nh_type;

    nh.pos=data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)){
        struct ipv6hdr *ip6h;
        struct icmp6hdr *icmp6h;

        nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

    }else if(nh_type == bpf_htons(ETH_P_IP)){

        struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;

    }

out:
	return XDP_PASS; 

}