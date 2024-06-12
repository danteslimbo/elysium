# elysium
## About elysium
`elysium` is a simple tool to stat arbitrary kprobes.

TODO:

- [ ] uprobe support.
- [ ] more filter options.

## TL;DR
Usage:
```bash
./elysium -h
Usage: ./elysium [options]
    Available options:
  -h, --help              show help
  -i, --interval uint32   set monitor time in seconds
  -k, --kprobe string     kprobe to be monitored
  -p, --pid uint32        filter pid
  -s, --self elysium      show stat of elysium itself, default `false`
  -t, --tid uint32        filter tid
  -v, --version           show version
```
Example, stat `__x64_sys_read` for 3 seconds,
and omit the `__x64_sys_read` called from elysium.
```bash
sudo ./elysium -k __x64_sys_read -i 3 

Fetching __x64_sys_read for 3 seconds...
Records:
Tid     Pid     Comm    Count   Ave Latency
372     372     systemd-journal 16      8699
759     750     gmain   8       2417
573     569     multipathd      4       4231
1734246 1734246 sshd    1       4544
1109    806     containerd      1       4031
```
Filter by pid:
```bash
sudo ./elysium -k __x64_sys_read -i 3  -p $(pidof containerd)

Fetching __x64_sys_read for 3 seconds...
Records:
Tid     Pid     Comm    Count   Ave Latency
895     806     containerd      4       2786
```

## FAQ
1. Why not BCC funccount?

Don't want to install BCC on servers.

2. Why not bpftrace?

We cannot pass a kprobe to be tracked to bpftrace scripts.
When I want to trace and stat different kprobes by one script,
I have to pass the kprobe to the bash script and render a bpftrace script.
This is also why I develop `elysium`.

```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <kprobe_name>"
  exit 1
fi

KPROBE_NAME=$1

cat <<EOL > trace.bt
#!/usr/bin/env bpftrace

BEGIN
{
  printf("Tracing kprobe %s\\n", "$KPROBE_NAME");
}

kprobe:$KPROBE_NAME
{
  @start[comm, tid] = nsecs;
  @result[comm, tid] = count();
}

kretprobe:$KPROBE_NAME
{
  @delta[comm, tid] = nsecs - @start[comm, tid];
  delete(@start[comm, tid]);
}

END
{
  clear(@start);
}
EOL

chmod +x trace.bt

bpftrace ./trace.bt
```
