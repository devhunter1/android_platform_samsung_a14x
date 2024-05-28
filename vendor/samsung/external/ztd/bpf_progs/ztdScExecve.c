
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY (DEBUG && 0)

#if DEBUG
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

DEFINE_BPF_MAP_GRW(sc_execve_data_map, HASH, uint64_t, sc_execve_data_t, 128, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", true,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
#endif

static inline __always_inline void onSyscallExecveEnter(sys_enter_data_t *args) {
    sc_execve_data_t data = {};
    data.event_time = bpf_ktime_get_boot_ns();
    data.pid_tgid = bpf_get_current_pid_tgid();
    data.uid_gid = bpf_get_current_uid_gid();

    bpf_probe_read_user_str(data.filename, sizeof(data.filename), POINTER_OF_USER_SPACE(args->args[0]));
    uint64_t argv_addr;
    void *argv_ptr;
#pragma unroll (ZT_MAX_ARGS)
    for (int i = 0; i < ZT_MAX_ARGS; i++) {
        argv_ptr = POINTER_OF_USER_SPACE(args->args[1] + (i * sizeof(void*)));
        if (argv_ptr == NULL) break;
        bpf_probe_read_user(&argv_addr, sizeof(uint64_t), argv_ptr);
        if (argv_addr == 0) break;
        bpf_probe_read_user_str(data.argv[i], sizeof(data.argv[i]), POINTER_OF_USER_SPACE(argv_addr));
    }
/*
 * Not interested...
 *
    uint64_t envp_addr;
    void *envp_ptr;
#pragma unroll (ZT_MAX_ARGS)
    for (int i = 0; i < ZT_MAX_ARGS; i++) {
        envp_ptr = POINTER_OF_USER_SPACE(args->args[2] + (i * sizeof(void*)));
        if (envp_ptr == NULL) break;
        bpf_probe_read_user(&envp_addr, sizeof(uint64_t), envp_ptr);
        bpf_probe_read_user_str(data.envp[i], sizeof(data.envp[i]), POINTER_OF_USER_SPACE(envp_addr));
    }
 */
    uint64_t key = data.pid_tgid;
    bpf_sc_execve_data_map_update_elem(&key, &data, BPF_ANY);
}

static inline __always_inline void onSyscallExecveExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();
    sc_execve_data_t *data = bpf_sc_execve_data_map_lookup_elem(&key);

    if (data) {
        data->ret = args->ret;
#ifdef USE_RINGBUF
        sc_data_t *output = bpf_sc_data_ringbuf_reserve();
        if (output == NULL) return;

        output->event = TRACE_EVENT_SYS_EXECVE;
        output->nr = NR_SYSCALL_EXECVE;
        __builtin_memcpy(&output->u.sc_execve.data.filename, data->filename,
                         sizeof(output->u.sc_execve.data.filename));
        __builtin_memcpy(&output->u.sc_execve.data.argv, data->argv,
                         sizeof(output->u.sc_execve.data.argv));
        output->u.sc_execve.data.event_time = data->event_time;
        output->u.sc_execve.data.pid_tgid   = data->pid_tgid;
        output->u.sc_execve.data.uid_gid    = data->uid_gid;
        output->u.sc_execve.data.ret        = data->ret;

        bpf_sc_data_ringbuf_submit(output);
#endif
        bpf_sc_execve_data_map_delete_elem(&key);
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_execve_enter)
(sys_enter_data_t *args) {
    if (args->id == NR_SYSCALL_EXECVE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallExecveEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_execve_exit)
(sys_exit_data_t *args) {
    if (args->id == NR_SYSCALL_EXECVE) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallExecveExit(args);
    }
    return 1;
}

LICENSE("GPL");