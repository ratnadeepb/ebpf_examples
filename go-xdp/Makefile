ARCH=$(shell uname -m)
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

TARGET := hello
TARGET_BPF := $(TARGET).bpf.o

# GO_SRC := $(shell find . -type f -name *.go)
# BPF_SRC := $(shell find . -type f -name *.bpf.c)

GO_SRC := *.go
BPF_SRC := *.bpf.c

# sudo cp libbpf/src/libbpf.a /usr/lib/x86_64-linux-gnu/
# sudo cp -r libbpf/src/build/usr/include/bpf /usr/include/bpf
LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a

.PHONY: all

all: $(TARGET) $(TARGET_BPF)


go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"

$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)

$(TARGET_BPF): $(BPF_SRC)
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf \
		-o $@ $<

.PHONY: clean
clean:
	go clean
	