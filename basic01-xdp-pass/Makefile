# XDP_TARGETS := xdp_pass_kern
# USER_TARGETS := xdp_pass_user

# LLC ?= llc
# CLANG ?= clang
# CC := gcc

# LIBBPF_DIR = ../libbpf/src/
# COMMON_DIR = ../common/

# include $(COMMON_DIR)/common.mk
# COMMON_OBJS := $(COMMON_DIR)/common_params.o


TARGET = xdp_pass

# For xdp_pass, make and also make user. The others don't have userspace programs

USER_TARGET = ${TARGET:=_user}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}
SKEL_OBJ = ${TARGET:=.skel.h}

# xdp: $(BPF_OBJ)
# 	bpftool net detach xdpgeneric dev enp1s0f1
# 	rm -f /sys/fs/bpf/$(TARGET)
# 	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
# 	bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(TARGET) dev enp1s0f1 

user:  $(SKEL_OBJ) $(USER_TARGET)

kernel: $(BPF_OBJ)

skel: $(SKEL_OBJ)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(SKEL_OBJ): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(USER_TARGET): %: %.c $(COMMON_OBJS)
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@  \
	 $^ -l:libbpf.a -lelf -lz # -l../../xdp-tools/lib/libxdp/libxdp.so

$(BPF_OBJ): %.o: %.c
	clang -S \
		-g \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -Ilibbpf/src\
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	bpftool net detach xdpgeneric dev enp1s0f1
	rm -f /sys/fs/bpf/$(TARGET)
	rm -f $(USER_TARGET)
	rm -rf $(SKEL_OBJ)
	rm $(BPF_OBJ)
	rm ${BPF_OBJ:.o=.ll}
