#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_ipv6.h"

#define TASK_COMM_LEN 16

struct event_t {
  u64 latency;
  u32 tid;
  u32 pid;
  char name[TASK_COMM_LEN];
} __attribute__((packed));

#define MAX_QUEUE_ENTRIES 10000
struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __type(value, struct event_t);
  __uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

#define MAX_TRACK_SIZE 4096
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, __u64);
  __uint(max_entries, MAX_TRACK_SIZE);
} start_ns_map SEC(".maps");

SEC("kprobe/kprobe_stat")
int kprobe_stat(struct pt_regs *ctx) {
  u32 tid = (u32)bpf_get_current_pid_tgid();
  u64 start_ns = bpf_ktime_get_ns();

  bpf_map_update_elem(&start_ns_map, &tid, &start_ns, BPF_ANY);

  return BPF_OK;
}

SEC("kretprobe/kretprobe_stat")
int BPF_KRETPROBE(kretprobe_stat) {
  struct event_t event = {};
  u64 tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)tgid;
  event.tid = tid;
  event.pid = tgid >> 32;
  
  __u64 *start_ns = bpf_map_lookup_elem(&start_ns_map, &tid);
  if (!start_ns) {
    return BPF_OK;
  }
  
  event.latency = bpf_ktime_get_ns() - *start_ns;
  int ret = bpf_get_current_comm(&event.name, sizeof(event.name));
  if (ret < 0) {
      bpf_printk("error when bpf_get_current_comm: %d\n", ret);
  }
  bpf_map_push_elem(&events, &event, BPF_EXIST);
  
  bpf_map_delete_elem(&start_ns_map, &tid);
  return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
