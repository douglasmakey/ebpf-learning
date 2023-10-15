#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define a structure to hold data to be collected
struct data_t {
    u32 uid;  // User ID
    char comm[TASK_COMM_LEN];  // The current process name
    char fname[NAME_MAX];  // File name
    int flags;  // Flags indicating mode of file access
};

BPF_PERF_OUTPUT(events);  // Declare a BPF map to transmit data to user space

// Function to be triggered on openat syscall
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    // Get current user ID and group ID
    u32 uid = bpf_get_current_uid_gid();
    // Assign user ID and flags to data structure
    struct data_t data = {};
    data.uid = uid;
    data.flags = flags;
    // Get the current process name of current task
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    // Get file name from user space
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)filename);
    // Submit data to events map for transmission to user space
    events.perf_submit(ctx, &data, sizeof(data));  
    return 0;  // Indicate successful execution
}