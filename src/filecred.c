#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "filecred.h"
#include "filecred.skel.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        if (level > LIBBPF_INFO)
                return 0;
        return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig) 
{
        exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
        struct data_t *e = data;

        printf("pid:%d\n"
               " uid: %u, gid: %u\n"
               " i_mode : %u\n"
               " i_uid: %u, i_gid:%u",
               e->pid, e->uid, e->gid,
               e->i_mode, e->i_uid, e->i_gid);
        
        return 0;
}

int main()
{
        struct ring_buffer *rb = NULL;
        struct filecred_bpf *skel;
        int err;

        libbpf_set_print(libbpf_print_fn);
        bump_memlock_rlimit();

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        skel = filecred_bpf__open_and_load();
        if (!skel) {
                fprintf(stderr, "Failed to open and load BPF skeleton.\n");
                return 1;
        }

        err = filecred_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "Failed to attach BPF skeleton\n");
                goto cleanup;
        }

        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
                err = -1;
                fprintf(stderr, "Failed to create ring buffer\n");
        }

        while (!exiting) {
                err = ring_buffer__poll(rb, 100);
                if (err == -EINTR) {
                        err = 0;
                        break;
                }
                if (err < 0) {
                        printf("Error polling ring buffer: %d\n", err);
                        break;
                }
        }

cleanup:
        ring_buffer__free(rb);
        filecred_bpf__destroy(skel);

        return err < 0 ? -err : 0;
}
