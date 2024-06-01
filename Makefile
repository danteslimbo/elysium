GO := go
GO_BUILD = CGO_ENABLED=1 $(GO) build
GO_GENERATE = $(GO) generate
GO_TAGS ?=
TARGET_GOARCH ?= amd64
GOARCH ?= amd64
TARGET=elysium
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
VERSION=$(shell git describe --tags --always)
LIBPCAP_ARCH ?= x86_64-unknown-linux-gnu

CC ?= gcc

elysium: *.o main.go */*.go
	CC=$(CC) GOARCH=$(TARGET_GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) \
		-ldflags "-w -s \
		-X 'github.com/danteslimbo/elysium/libs.Version=${VERSION}'"

*.o: bpf/*.c
	TARGET_GOARCH=$(TARGET_GOARCH) $(GO_GENERATE)

clean:
	rm -f elysium kprobeelysium_*
