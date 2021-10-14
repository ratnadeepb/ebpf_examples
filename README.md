# Using EBPF

## Setup

[Reference](https://arthurchiao.art/blog/firewalling-with-bpf-xdp/)
[Dropbox](https://paper.dropbox.com/doc/BPF-Setup--BUI003bDeTGlJlnYEQpGj9ipAg-haT7cbcjpOdR8mKn9FKTr)

```bash
sudo apt install libelf-dev linux-libc-dev libc6-dev-i386 build-essential build-essential # gcc-multilib linux-tools-$(uname -r) linux-headers-$(uname -r) linux-headers-generic linux-tools-common linux-tools-generic
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make
sudo make install
sudo apt install llvm # llc
sudo apt install linux-tools-common # bpftool
```

## Compiling

```bash
clang -O3 -Wall -target bpf -c code. -o code.o
```