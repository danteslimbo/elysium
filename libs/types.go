package libs

import (
	"fmt"
	"os"
	"sort"

	flag "github.com/spf13/pflag"
)

type Flags struct {
	ShowVersion bool
	ShowHelp    bool

	Time     uint32
	Kprobe   string
	ShowSelf bool
}

func (f *Flags) SetFlags() {
	flag.BoolVarP(&f.ShowVersion, "version", "v", false, "show version")
	flag.BoolVarP(&f.ShowHelp, "help", "h", false, "show help")
	flag.Uint32VarP(&f.Time, "time", "t", 0, "set monitor time in seconds")
	flag.StringVarP(&f.Kprobe, "kprobe", "k", "", "kprobe to be monitored")
	flag.BoolVarP(&f.ShowSelf, "self", "s", false, "show stat of `elysium` itself, default `false`")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [options] \n", os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "    Available options:\n")
		flag.PrintDefaults()
	}
}

func (f *Flags) PrintHelp() {
	flag.Usage()
}

func (f *Flags) Parse() {
	flag.Parse()
}

type Event struct {
	Latency uint64
	Tid     uint32
	Pid     uint32
	Name    [16]int8
}

func (e *Event) GetName() string {
	bytes := e.Name[:]
	runes := make([]rune, len(bytes))
	for i, b := range bytes {
		runes[i] = rune(b)
	}
	return string(runes)
}

type Record struct {
	Latency uint64
	Count   uint64
	Comm    string
	Tid     uint32
	Pid     uint32
}

type Records map[uint32]*Record

func (r Records) PrintRecords(showSelf bool) {
	_, _ = fmt.Fprintln(os.Stderr, "Records:")
	_, _ = fmt.Fprintln(os.Stderr, "Tid\tPid\tComm\tCount\tAve Latency")
	records := []*Record{}
	for _, record := range r {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Count > records[j].Count
	})
	selfPid := os.Getpid()
	for _, v := range records {
		if !showSelf {
			if v.Pid == uint32(selfPid) {
				continue
			}
		}
		_, _ = fmt.Fprintf(os.Stderr, "%d\t%d\t%s\t%d\t%d\n", v.Tid, v.Pid, v.Comm, v.Count, v.Latency/v.Count)
	}
}
