package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/danteslimbo/elysium/libs"
)

func main() {
	flags := libs.Flags{}
	flags.SetFlags()
	flags.Parse()

	if flags.ShowHelp {
		flags.PrintHelp()
		os.Exit(0)
	}

	if flags.ShowVersion {
		fmt.Printf("elysium %s\n", libs.Version)
		os.Exit(0)
	}

	if flags.Kprobe == "" {
		fmt.Println("Please specify --kprobe/-k")
		os.Exit(1)
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var bpfSpec *ebpf.CollectionSpec
	bpfSpec, err := LoadKProbeElysium()
	if err != nil {
		log.Fatalf("failed to load KProbeElysium: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100
	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer coll.Close()
	kp, err := link.Kprobe(flags.Kprobe, coll.Programs["kprobe_stat"], nil)
	if err != nil {
		log.Fatalf("Failed to link kprobe: %s\n%+v", flags.Kprobe, err)
	}
	defer kp.Close()
	krp, err := link.Kretprobe(flags.Kprobe, coll.Programs["kretprobe_stat"], nil)
	if err != nil {
		log.Fatalf("Failed to link kretprobe: %s\n%+v", flags.Kprobe, err)
	}
	defer krp.Close()

	records := make(libs.Records)
	defer func() {
		records.PrintRecords(flags.ShowSelf)
	}()

	var event libs.Event
	events := coll.Maps["events"]
	c := time.Tick(time.Duration(flags.Time) * time.Second)
	_, _ = fmt.Fprintf(os.Stderr, "Fetching %s for %d seconds...\n", flags.Kprobe, flags.Time)
	for {
		for {
			if err := events.LookupAndDelete(nil, &event); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-c:
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		if _, ok := records[event.Tid]; ok {
			records[event.Tid].Count++
			records[event.Tid].Latency += event.Latency
		} else {
			records[event.Tid] = &libs.Record{
				Count:   1,
				Latency: event.Latency,
				Pid:     event.Pid,
				Tid:     event.Tid,
				Comm:    event.GetName(),
			}
		}

		select {
		case <-c:
			return
		case <-ctx.Done():
			return
		default:
		}
	}
}
