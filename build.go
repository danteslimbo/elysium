//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip KProbeElysium ./bpf/kprobe.c -- -DOUTPUT_SKB -I./bpf/headers -Wno-address-of-packed-member

package main
