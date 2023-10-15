from bcc import BPF

# Define the eBPF program as a string.
bpf_program = """
#include <uapi/linux/ptrace.h>

// Define a kprobe for the clone system call.
int syscall__clone(struct pt_regs *ctx) {
    // Print a message each time the clone system call is invoked.
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Load the eBPF program.
b = BPF(text=bpf_program)

# Attach the kprobe defined in the eBPF program to the clone system call.
event_name = b.get_syscall_prefix().decode() + 'clone'
b.attach_kprobe(event=event_name, fn_name="syscall__clone")

# Loop and print the output of the eBPF program.
try:
    print("Attaching kprobe to sys_clone... Press Ctrl+C to exit.")
    b.trace_print()
except KeyboardInterrupt:
    pass