// SPDX-License-Identifier: GPL-2.0
//
// BPF LSM exec guard for vulnetix-sensor. Refuses an exec whose file is in the
// `blocked` map, keyed by inode number and device, and reports each refusal on
// the `events` ring buffer. The sensor fills the map from its rules; nothing
// here decides what to block.
//
// Rebuild with `go generate ./internal/sensor/lsmguard` (clang, libbpf headers).
// The struct definitions are the few fields this program reads, marked for
// CO-RE relocation so one object runs on any kernel with BTF.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef unsigned int u32;
typedef unsigned long long u64;

struct super_block {
	u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

struct file_key {
	u64 ino;
	u32 dev;
	u32 pad;
};

struct refusal {
	u64 ino;
	u32 dev;
	u32 rule;
	u32 pid;
	u32 enforced;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, u32);
} blocked SEC(".maps");

// enforce[0] is 1 to refuse, 0 to report only.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} enforce SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("lsm/bprm_check_security")
int vulnetix_exec_guard(unsigned long long *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[0];
	int ret = (int)ctx[1];
	struct file_key key = {};
	struct refusal ev = {};
	u32 zero = 0;
	u32 *rule, *on;

	// An earlier LSM already refused it.
	if (ret != 0)
		return ret;

	key.ino = bprm->file->f_inode->i_ino;
	key.dev = bprm->file->f_inode->i_sb->s_dev;
	rule = bpf_map_lookup_elem(&blocked, &key);
	if (!rule)
		return 0;

	on = bpf_map_lookup_elem(&enforce, &zero);
	ev.ino = key.ino;
	ev.dev = key.dev;
	ev.rule = *rule;
	ev.pid = bpf_get_current_pid_tgid() >> 32;
	ev.enforced = on && *on;
	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

	return ev.enforced ? -1 /* EPERM */ : 0;
}

char LICENSE[] SEC("license") = "GPL";
