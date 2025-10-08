#include "../vmlinux/vmlinux.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <netinet/ip_icmp.h>

#include <XDP.hpp>
#include <xdp/parsing_helpers.h>
#include <xdp/xdp_stats_kern.h>

#include "errno.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
* current version of the xdp program just redirect the 
* recevied packet back to the interface from where it was
* received. The only problem here is that we are not having 
* able to send it to any other vm cause they should have veth
* or this bpf program installed in order to further process the data
* packets.
*/
struct redirect_stats *rs;
int err;

static long send_data_cb(struct bpf_dynptr *dynptr, void *context){
	struct packet_stats *p;
	

	err = bpf_dynptr_read(rs,sizeof(rs),dynptr, 0 , 0);
	if(err) return 0;

	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;

	p = (struct packet_stats *)bpf_ringbuf_reserve(&kernel_ringbuff, sizeof(*p), 0);
    if (!p)
        return 0;

	//TODO store the packet data leng here;
	p->pac_len=10;

	bpf_ringbuf_submit(p, 0);
    return 0;
}

SEC("xdp")
int xdp_redirecting(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    
	//reply and actions
    __u32 pass_packets = XDP_PASS;
	__u32 echo_reply;

	//header and return type intialised
    struct hdr_cursor nh;
    int eth_type;
	int ip_type;
	int icmp_type;

	//storing of the ipv6,icmp,eth
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct icmphdr_common *icmphdr;

    nh.pos=data;

	//parse the required header in order to get the type of ip
    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}
	long num_samples;
	num_samples = bpf_user_ringbuf_drain(&user_ringbuff, send_data_cb, NULL, 0);

	if(!err){
		swap_dst_mac(eth,rs->src);
		pass_packets = bpf_redirect_map(&tx_port, 0, 0);
	}
	//TODO take the destination source address and push it in the eth address and 
	//just get the stats accordingly


out:
	return pass_packets;

}