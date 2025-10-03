KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)

CLANG ?= clang
CFLAGS = -O2 -target bpf \
    -I$(KERNEL_HEADERS)/include \
    -I$(KERNEL_HEADERS)/include/uapi \
    -I$(KERNEL_HEADERS)/include/generated \
    -I$(KERNEL_HEADERS)/include/generated/uapi \
	-I$(KERNEL_HEADERS)/arch/x86/include/uapi


all: xdp_pass_kernel.o

xdp_pass_kernel.o: xdp_pass_kernel.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
