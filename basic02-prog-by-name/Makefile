# COMMON_DIR = ../common/
# COMMON_OBJS := $(COMMON_DIR)/common_params.o


TARGET = xdp

# For xdp_pass, make and also make user. The others don't have userspace programs

USER_TARGET = ${TARGET:=_loader}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}
SKEL_OBJ = ${TARGET:=.skel.h}

# user:  $(SKEL_OBJ) $(USER_TARGET)
user:  $(USER_TARGET)

kernel: $(BPF_OBJ)

skel: $(SKEL_OBJ)

$(SKEL_OBJ): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(USER_TARGET): %: %.c $(COMMON_OBJS)
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@  \
	 $^ -l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: %.c
	clang -S \
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
	# bpftool net detach xdpgeneric dev enp1s0f1
	# rm -f /sys/fs/bpf/$(TARGET)
	rm -rf $(USER_TARGET)
	rm -rf $(SKEL_OBJ)
	rm $(BPF_OBJ)
	rm ${BPF_OBJ:.o=.ll}
