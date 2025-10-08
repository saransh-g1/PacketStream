#include <vmlinux.h>
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};

struct hdr_cursor {
	void *pos;
};

struct redirect_stats {
	int id;
	unsigned char src[ETH_ALEN];
};
struct packet_stats {
	int pid_t;
	long pac_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256*1024);
} kernel_ringbuff SEC(".maps");


struct { 
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256*1024);
} user_ringbuff SEC(".maps");


static __always_inline void swap_dst_mac(struct ethhdr *eth, unsigned char *dest)
{
	memcpy(&eth->h_dest, dest, ETH_ALEN);
	return;
}


