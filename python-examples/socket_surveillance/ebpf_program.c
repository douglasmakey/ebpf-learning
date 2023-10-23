#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// Enumeration to represent the type of event being recorded
enum event_type {
    CONNECTED,
    DATA_SENT,
    CLOSED,
};

// Structure to hold data that will be sent to user space
struct data_t {
    u32 tgid;                // Thread Group ID
    int fdf;                 // Socket File Descriptor
    char comm[TASK_COMM_LEN];// Command Name
    u32 ip_addr;             // IP Address
    int ret;                 // Return Value
    enum event_type type;    // Event Type
};


BPF_PERF_OUTPUT(sockets);  // Declare a BPF map to transmit data to user space

int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr *addr, int addrlen) {
    u32 tgid = bpf_get_current_pid_tgid();
    struct sockaddr_in addr_in = {};
    bpf_probe_read_user(&addr_in, sizeof(addr_in), addr);

    // Check if address family is AF_INET
    if (addr_in.sin_family == AF_INET) {
        struct data_t data = {};
        // Set Thread Group ID
        data.tgid = tgid;
         // Set Socket File Descriptor
        data.fdf = sockfd;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        // Set IP Address
        data.ip_addr = addr_in.sin_addr.s_addr;
        data.type = CONNECTED;
        // Submit data to user space
        sockets.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

int syscall__close(struct pt_regs *ctx, int sockfd) {
    u32 tgid = bpf_get_current_pid_tgid();
    struct data_t data = {};
    // Set Thread Group ID
    data.tgid = tgid;
    // Set Socket File Descriptor
    data.fdf = sockfd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = CLOSED;
    // Submit data to user space
    sockets.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Structure to hold temporary data for sendto syscall
struct send_info_t {
    u32 tgid;
    int fdf;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u32, struct send_info_t);

int syscall__sendto(struct pt_regs *ctx, int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, int addrlen) {
    u32 tgid = bpf_get_current_pid_tgid();
    struct send_info_t info = {};
    if (bpf_get_current_comm(&info.comm, sizeof(info.comm)) == 0) {
        // Set Thread Group ID
        info.tgid = tgid;
        // Set Socket File Descriptor
        info.fdf = sockfd;
        // Update temporary data map
        infotmp.update(&tgid, &info);
    }

    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid();

    struct data_t data = {};
    struct send_info_t *infop;

    // Lookup the entry for our sendto
    infop = infotmp.lookup(&tgid);
    if (infop == 0) {
        // missed entry
        return 0;
    }

    // Set Thread Group ID
    data.tgid = infop->tgid;
    // Set Socket File Descriptor
    data.fdf = infop->fdf;
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), infop->comm);
    // Assign the amount of data sent to the ret field, as obtained from the register context
    data.ret = PT_REGS_RC(ctx);
    data.type = DATA_SENT;
    // Submit data to user space
    sockets.perf_submit(ctx, &data, sizeof(data));
    // Delete temporary entry
    infotmp.delete(&tgid);
    return 0;
}