TARGET = xdp
USER_TARGET = ${TARGET:=_loader}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}
SKEL_OBJ = ${TARGET:=.skel.h}

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
	rm -rf $(USER_TARGET)
	rm -rf $(SKEL_OBJ)
	rm $(BPF_OBJ)
	rm ${BPF_OBJ:.o=.ll}