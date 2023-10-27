
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define the SIGKILL signal, which instructs the system to terminate the process
#define SIGKILL 9

// Define a key structure to hold the file name
struct key_t {
  char fname[NAME_MAX];
};

// Map to store secret files and their associated security levels
BPF_HASH(secret_files, struct key_t, int);

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    struct key_t key = {};
    // Get current user ID and group ID
    u32 uid = bpf_get_current_uid_gid();

    // Read the file name from user space into the key structure
    bpf_probe_read_user_str(&key.fname, sizeof(key.fname), (void *)filename);
    // Look up the file name in the secret_files map to get its security level
    int *security_level = secret_files.lookup(&key);
    if (security_level != 0) {
        // Check if the user is root
        if (uid == 0) {
            bpf_trace_printk("Root user opening secret file %s \\n", key.fname);
            return 0;
        }

        bpf_trace_printk("Non-root user attempting to open secret file %s with security level %d \\n", key.fname, *security_level );
        if (*security_level == 1) {
            // Override the return value of the syscall to indicate permission denied
            bpf_override_return(ctx, -EACCES);
        } else if (*security_level > 1) {
            // If security level is gt than 1, send the SIGKILL signal to terminate the process
            bpf_send_signal(SIGKILL);
        }
    }
    
    return 0;
}