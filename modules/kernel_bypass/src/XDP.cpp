#include "../vmlinux/vmlinux.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <common_define.hpp>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct option_wrapper {
  struct option option;
  char *help;
  char *metavar;
  bool required;
};


static const struct option_wrapper cli_commands[]= {
    {{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },
};

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{

}

void usage(const char *prog_name, const char *doc,
	   const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *long_options,
			struct config *cfg, const char *doc);



static int write_iface_params(int map_fd, unsigned char *src, unsigned char *dest)
{
    if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
        fprintf(stderr,
            "WARN: Failed to update bpf map file: err(%d):%s\n",
            errno, strerror(errno)
        );
        return -1;
    }

    printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;

}


#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";


int main(int agrc, char **argv){
    int i;
    int len;

    int map_fd;
	bool redirect_map;

    char pin_dir[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];

    struct config cfg = {
        .ifindex = -1,
        .redirect_ifindex = -1,
    }

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);
    
    if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, cli_commands, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

    if (parse_mac(cfg.src_mac, src) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.src_mac);
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.dest_mac, dest) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.dest_mac);
		return EXIT_FAIL_OPTION;
	}

    	map_fd = -1;

	printf("map dir: %s\n", pin_dir);

	if (redirect_map) {
		/* setup a virtual port for the static redirect */
		i = 0;
		bpf_map_update_elem(map_fd, &i, &cfg.redirect_ifindex, 0);
		printf("redirect from ifnum=%d to ifnum=%d\n", cfg.ifindex, cfg.redirect_ifindex);

		/* Assignment 3: open the redirect_params map corresponding to the cfg.ifname interface */
		map_fd = -1;

		/* Setup the mapping containing MAC addresses */
		if (write_iface_params(map_fd, src, dest) < 0) {
			fprintf(stderr, "can't write iface params\n");
			return 1;
		}
	}

	return EXIT_OK;

}
