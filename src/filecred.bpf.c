#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "filecred.h"

struct {
        __uint(type,BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("fentry/acl_permission_check")
int BPF_PROG(fentry_acl_permission_check, 
                struct mnt_idmap *idmap, struct inode *inode, int mask)
{
        struct data_t *data;

        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
                return 0;

        data->pid = bpf_get_current_pid_tgid();
        data->tgid = bpf_get_current_pid_tgid() >> 32;

        data->uid = bpf_get_current_uid_gid();
        data->gid = bpf_get_current_uid_gid() >> 32;

        data->i_mode = inode->i_mode;
        data->i_uid = inode->i_uid.val;
        data->i_gid = inode->i_gid.val;

        bpf_ringbuf_submit(data,0);
        return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
