#include <argp.h>
#include "XDP.h"
#include <signal.h>
#include <stdbool.h>
#include "XDP.skel.h"

static volatile bool exiting = false;
struct user_ringbuff *u_b = NULL;

static void sig_handler(int sig)
{
	exiting = true;
}
static void write_samples(struct user_ring_buffer *ringbuf){
	struct redirect_stats *rs;
	int err;
	//get the required stats of next mac address of in the network
	//and redirect the data

	rs = user_ring_buffer__reserve(ringbuf, sizeof(*rs));
	if (!rs)
	{
		err = -errno;
		goto done;
	}

	user_ring_buffer__submit(ringbuf, rs);

	done:
		drain_current_samples();
}

static void handle_event(void *ctx, void *data, size_t data_sz){
	const struct packet_stats *e = data;

	printf("%d %d\n",
		    e->pid_t, e->pac_len);
	write_samples(u_b);

}

int main(){
	//what are the required function ove rhere
	 struct XDP_bpf *skel;
	 struct kernel_ringbuff *k_b= NULL;
	 int err;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = XDP_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	err = user_ringbuf_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = user_ringbuf_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	k_b = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ringbuff), handle_event, NULL, NULL);
	if (!k_b)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	u_b = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuff), NULL);

	write_samples(u_b);

	while (!exiting)
	{
		err = ring_buffer__poll(k_b, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
	sig_handler(1);
	cleanup:;

}