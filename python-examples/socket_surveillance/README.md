# IPv4 Socket Surveillance - Tracing using Kprobe, kretprobe and maps with BCC

In my previous [article](https://www.kungfudev.com/blog/2023/10/14/the-beginning-of-my-ebpf-journey-kprobe-bcc), I explored the fundamentals of eBPF, a technology enabling interaction with the Linux kernel without altering kernel code. I discussed eBPF's programmable hooks into the kernel, its event-driven nature, and highlighted its utility in system monitoring through syscall hooking. The article also introduced eBPF programming, emphasizing the ease of integrating eBPF programs within Python scripts using BCC. I touched on a simple `kprobe` example, setting the stage for a deeper dive. This time, I aim to delve further into `kprobe` and `kretprobe`, showcasing the versatility of eBPF `maps` through practical demonstrations, to illuminate eBPF's power in system monitoring and customization, expanding on our prior explorations.

## The probes siblings: kprobe and kretprobe

The tools `kprobe` and `kretprobe` are probing mechanisms within the eBPF ecosystem. `kprobe` is used to inspect data at the entry of a `kernel` function, while `kretprobe` is used at the function's exit. Together, these tools allow us to monitor, analyze, and debug kernel behaviors by capturing both function arguments and return values. Specifically, `kretprobe`, in particular, is crucial because it captures the return values, showing the result of kernel function calls. This way, we can get a full picture of how functions behave, helping us to understand the system better.

Here is a simplified illustration about `kprobe` and `kretprobe` in a syscall:

```text
             Kernel Function
              "openat,clone"
             ---------------
             |             |
             |             |
             |-------------|
Kprobe -->   | Entry Point |
             |     args    |
             |-------------|
             |             |
             |   Function  |
             |    Body     |
             |             |
             |-------------|
Kretprobe -> | Exit Point  |
             |return values|
             |-------------|

```

### Why kretprobe is important?

Imagine you are creating a straightforward memory profiling tool to monitor which applications are consuming more memory. By employing `kprobe` on `malloc`, you can capture the size of the requested memory allocation. However, it’s `kretprobe` on `malloc` that unveils the return value, indicating whether the memory allocation succeeded or failed. By comparing the arguments and return values, you garner crucial insights into system behavior, aiding in tracking memory usage more effectively and aligning with your objective of keeping a close eye on memory consumption across different applications.

Thus, in simplistic terms, `kprobe` grants us insight into the system's intention to execute a particular action, while `kretprobe` informs us whether that intention was successfully carried out and reveals the outcomes of the action.

## Maps

eBPF maps offer a mechanism to store data in kernel space, making it accessible to user space, and also facilitating data sharing between different probes. This feature is instrumental for numerous eBPF use cases such as monitoring, tracing, and networking tasks. However, it's worth noting that eBPF's design enforces certain limitations to ensure system safety and performance, which in turn shapes how maps can be used. Through this experiment, we aim to highlight the utility and versatility of eBPF maps, while also navigating the inherent limitations of eBPF, showcasing how maps can bridge interactions between kernel space, user space, and various probes.

> BPF 'maps' provide generic storage of different types for sharing data between kernel and user space. There are several storage types available, including hash, array, bloom filter and radix-tree. Several of the map types exist to support specific BPF helpers that perform actions based on the map contents. The maps are accessed from BPF programs via BPF helpers which are documented in the [man-pages](https://www.kernel.org/doc/man-pages/) for [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
> 
> https://docs.kernel.org/bpf/maps.html

As discussed, eBPF maps serve two significant scenarios:

**Bridging `user-space` and `kernel-space`.**

eBPF maps act as a conduit for data flow between user-space and kernel-space, allowing data to be shared and accessed across these two realms.

```txt
         Kernel Space                         User Space
        +------------------+                 +-------------------+
        |                  |                 |                   |
        |   eBPF Program   |                 |  User Application |
        |                  |   eBPF Maps     |                   |
        | +-------------+  |<--------------->| +---------------+ |
        | | Probe Logic |  |    Interface    | | Map Interface | |
        | +-------------+  |                 | +---------------+ |
        |                  |                 |                   |
        +------------------+                 +-------------------+

```

**Facilitating Data Exchange between `probes`.**

Enabling data sharing between probes within the same space.

```txt
Kernel Space
------------------------------------------------
|              |                   |           |
|   kprobe     |      eBPF Map     | kretprobe |
|   on syscall |                   | on syscall|
|   entry      |    <---------->   | exit      |
|              |     Data Share    |           |
------------------------------------------------
```

### Why maps are importants ?

The eBPF virtual environment has a stack size limitation of `512 bytes`, which imposes a constraint on the amount of data that can be handled within an eBPF program during its execution. This limitation necessitates alternative mechanisms for handling larger data sets. eBPF maps emerge as a crucial solution to this challenge. They provide a means to store data off the stack, allowing for more extensive data handling than what the stack permits. Unlike the traditional stack, eBPF maps offer a key/value data structure that is accessible from the eBPF program via a set of helpers, and the data stored in these maps persists across program invocations. This feature of eBPF maps essentially extends the data handling capabilities of eBPF programs, overcoming the stack size limitation and enabling more complex and data-intensive operations within the eBPF ecosystem.

Once more, this is a simplified glance at eBPF maps, setting aside some complexities which we plan to delve into and explore in further articles.

## The experiment: IPv4 Socket Surveillance

In this experiment, we will employ the previously discussed elements: `kprobe`, `kretprobe`, and `maps`. Our objective is to craft a ULTRA simple tool to monitor IPv4 socket activity on the machine. Initially, as a socket opens, the tool will capture socket information such as the socket file descriptor and the destination IP address. Following this, it will track the volume of data transmitted through that particular socket. This endeavor effectively harnesses the capabilities of `kprobe`, `kretprobe`, and `maps` to monitor and log the socket communication data accurately.

Similar to our previous experiment, our aim is to identify the syscalls involved when working with sockets, particularly during the process of connecting to the internet. For this illustration, we will utilize the `curl` command as our test case and employ `strace` to explore and trace the syscalls associated with socket interactions:

```bash
strace -e network -f curl --http1.1 http://www.kungfudev.com/
...
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("76.76.21.241")}, 16) = -1 EINPROGRESS (Operation now in progress)
...
sendto(5, "GET / HTTP/1.1\r\nHost: www.kungfu"..., 81, MSG_NOSIGNAL, NULL, 0) = 81
recvfrom(5, "HTTP/1.0 308 Permanent Redirect\r"..., 102400, 0, NULL, NULL) = 172
...
close(5) = 0
```


In the output above, we observe a sequence of syscalls representing the flow of socket operations from a client's perspective. This sequence commences with the creation of a socket via the `socket` syscall, followed by an attempt to connect to a server using the `connect` syscall. Post a successful connection, data transmission occurs through the `sendto` syscall, and reception of data is handled by the `recvfrom` syscall. Ultimately, the `close` syscall is invoked to terminate the socket connection.

For the purposes of our experiment, we have chosen to trace the `connect`, `sendto`, and `close` syscalls. Although the `socket` syscall marks the inception of a socket, our focus is primarily directed towards the operations post the establishment of a connection.

### Kernel Space

We'll start by examining the `C` code **our kernel space app** first.

```c
// Enumeration to represent the type of event being recorded
enum event_type {
    CONNECTED,
    DATA_SENT,
    CLOSED,
};

// Structure to hold data that will be sent to user space
struct data_t {
    u32 tgid;                // Thread ID
    int fdf;                 // Socket File Descriptor
    char comm[TASK_COMM_LEN];// The current process name
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
        // Set Thread ID
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
    // Set Thread ID
    data.tgid = tgid;
    // Set Socket File Descriptor
    data.fdf = sockfd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = CLOSED;
    // Submit data to user space
    sockets.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

```

The things to highlight from this code are:

* **System Call Handlers**:
	* Two functions, `syscall__connect` and `syscall__close`, are delineated to handle the `connect` and `close` system calls, respectively. For simplicity and brevity in this experiment, we employ `kprobe` and operate under the assumption that the system calls will always succeed.
	* Each function retrieves the current process and thread identifiers, and collects relevant data, such as the socket file descriptor and, in the case of `syscall__connect`, the IP address.
	* The data is populated into a `struct data_t` instance, with the `type` field set to `CONNECTED` or `CLOSED` as appropriate.
	* The `sockets.perf_submit()` function is called to transmit the collected data to user space.
* **IPv4 Address Family Check**:
	* In the `syscall__connect` function, there is a specific check for the address family using the condition `if (addr_in.sin_family == AF_INET) {}`. This check ensures that the subsequent code block, which collects and transmits data, only executes when the address family is IPv4.
* **Use of BPF Helper Functions**:
	* The code employs BPF helper functions like `bpf_get_current_pid_tgid()` to retrieve the current process and thread IDs, `bpf_probe_read_user()` to safely read user-space data, and `bpf_get_current_comm()` to obtain the process name of the current process.

Utilizing these two probes enables us to trace both the connection and closure of IPv4 sockets, subsequently transmitting this information to the user space. It's important to note that within the `syscall_close` probe, we lack the mechanism to filter out the sockets being closed. However, this limitation will be addressed in the user space, where we have the capacity to handle and filter out the specific sockets of interest.

Having addressed the events of connection and closure, we now turn our attention to handling the event of data transmission through the opened sockets, for which we will employ the `sendto` syscall. This time, we'll utilize both `kprobe` and `kretprobe` to obtain a comprehensive understanding of this syscall invocation, enabling us to capture the necessary data at the entry and exit points of the syscall, thereby gaining insight into the amount of data successfully transmitted.

>  The _sendto_() function shall send a message through a connection-mode or connectionless-mode socket.
>  
>  Upon successful completion, _sendto_() shall return the number of bytes sent. Otherwise, -1 shall be returned
>  https://man7.org/linux/man-pages/man3/sendto.3p.html

```c

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
        // Set Thread ID
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

    // Set Thread ID
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
```

The things to highlight from this code are:

1. **Inter-Probe Data Sharing through Maps**:
	1. A crucial aspect of this code snippet is the use of the BPF hash map `infotmp` to share data between probes, specifically, between the `kprobe` and `kretprobe` of the `sendto` syscall.
	2. In the `syscall__sendto` function (kprobe), essential data regarding the syscall is captured and stored in the `infotmp` map using the thread ID as the key. This data includes the thread ID, socket file descriptor, and the current process name.
	3. Later, in the `trace_return` function (kretprobe), the same `infotmp` map is accessed to retrieve the temporarily stored data using the thread ID. This shared data is then used to populate a new structure which is submitted to user space, post which the temporary data entry is deleted from the map.
	4. In this example, the inter-probe data sharing shines through, aiding in understanding the success or return value of the syscall. Initially, at the entry point, we capture the relevant arguments data and store it in the map. Later, during the `kretprobe`, we ascertain the success of the syscall and make use of the initially captured data from the map to match and submit the data. This demonstrates a practical way to correlate the syscall entry and exit points.
3. **Trace Return Handler**:
    - The `trace_return` function is defined to handle the trace return of the `sendto` syscall.
    - It looks up the temporary data entry in `infotmp`, and if found, populates a `struct data_t` instance with the relevant data.
    - It reads the return value from the register context, which indicates the amount of data successfully sent through the socket, and sets the event type to `DATA_SENT`. This way, by examining the return value, we can ascertain the quantity of data transmitted during the `sendto` syscall.
    - It then submits this data to user space using the `sockets` BPF map and deletes the temporary data entry from `infotmp`.
- **Data Cleanup**:
	- The `infotmp.delete(&tgid)` line within `trace_return` function ensures that temporary data entries are cleaned up from the `infotmp` hash map once they are no longer needed, helping in managing the memory usage of the BPF program.

### User space

Continuing with the `Python` code for our user space app, the code remains straightforward and shares similarity to our previous experiment, hence there isn't much to elaborate on it.

```python
from bcc import BPF
import ctypes as ct
import socket
import struct
from enum import Enum


TASK_COMM_LEN = 16
SOCKETS = {}

class EventType(Enum):
    CONNECTED = 0
    DATA_SENT = 1
    CLOSED = 2

class SocketInfo(ct.Structure):
    _fields_ = [
        ("tgid", ct.c_uint32),
        ("fdf", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ip_addr", ct.c_uint32),
        ("ret", ct.c_int),
        ("type", ct.c_uint),
    ]

def print_event(cpu, data, size):
    e = ct.cast(data, ct.POINTER(SocketInfo)).contents
    comm_id = f"{e.comm.decode()}-{e.tgid}"
    match e.type:
        case EventType.CONNECTED.value:
            print(f"The comm: {comm_id} connected a socket with FD: {e.fdf} to IP: {socket.inet_ntoa(struct.pack('I', e.ip_addr))}")
            SOCKETS[comm_id] = e
        case EventType.CLOSED.value:
            if comm_id in SOCKETS:
                print(f"The comm: {e.comm.decode()}-{e.tgid} closed the socket with FD: {e.fdf}") 
        case EventType.DATA_SENT.value:
                if comm_id in SOCKETS:
                    print(f"The comm: {e.comm.decode()}-{e.tgid} sent {e.ret} bytes through socket FD: {e.fdf}") 
        case _:
            print("Unknown event")


def main():
    # Define the eBPF program as a string.
    with open("ebpf_program.c", "r") as f:
        bpf_program = f.read()

    # Load the eBPF program.
    b = BPF(text=bpf_program)

    # Attach the kprobe defined in the eBPF program to the clone system call.
    connect_e = b.get_syscall_fnname("connect").decode()
    close_e = b.get_syscall_fnname("close").decode()
    sendto_e = b.get_syscall_fnname("sendto").decode()
    b.attach_kprobe(event=connect_e, fn_name="syscall__connect")
    b.attach_kprobe(event=close_e, fn_name="syscall__close")
    b.attach_kprobe(event=sendto_e, fn_name="syscall__sendto")
    b.attach_kretprobe(event=sendto_e, fn_name="trace_return")

    # Loop and print the output of the eBPF program.
    b["sockets"].open_perf_buffer(print_event)

    try:
        print("Attaching probes... Press Ctrl+C to exit.")
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
```


Upon executing the command `sudo python3 app.py` in one terminal, and subsequently running the curl command `curl --http1.1 http://www.kungfudev.com` in another terminal, we set the stage for observing the interaction between the eBPF program and the network operations initiated by the curl request.

```bash
sudo python3 app.py
Attaching probes... Press Ctrl+C to exit.
The comm: curl-128345 connected a socket with FD: 7 to IP: 127.0.0.53
The comm: curl-128345 closed the socket with FD: 7
The comm: curl-128345 closed the socket with FD: 7
The comm: curl-128345 sent 20 bytes through socket FD: 7
The comm: curl-128345 closed the socket with FD: 7
The comm: curl-128345 connected a socket with FD: 7 to IP: 76.76.21.9
The comm: curl-128345 connected a socket with FD: 7 to IP: 76.76.21.123
The comm: curl-128345 closed the socket with FD: 7
The comm: curl-128345 sent 1 bytes through socket FD: 6
The comm: curl-128344 connected a socket with FD: 5 to IP: 76.76.21.9
The comm: curl-128344 sent 81 bytes through socket FD: 5
The comm: curl-128344 closed the socket with FD: 5
The comm: curl-128344 closed the socket with FD: 3
The comm: curl-128344 closed the socket with FD: 4
```

As demonstrated by the output above, employing `kprobe`, `kretprobe`, and `maps` empowers us to craft interesting utilities. While the app showcased is quite simplistic, it confirms the potential to build truly engaging and insightful tools with the help of eBPF. Through this basic exploration, we've scratched the surface of what's achievable, paving the way for more complex and insightful creations in the future.

We know that the process of examining network operations is indeed more complex, involving a multitude of syscalls and a complex flow subject to various system conditions among other factors. However, for the purpose of this demonstration, we've chosen to keep things straightforward to better convey the core concepts and potential of eBPF's probing capabilities.

All the code can be found in my [repository](https://github.com/douglasmakey/ebpf-learning).

## To conclude

In this small exploration, we delved into using eBPF features. The use of `kprobe` and `kretprobe` allowed us to capture events at both the entry and exit points of syscalls, providing this time a clear picture of the network activity. Additionally, the use of maps facilitated sharing data between probes, showcasing a practical way to correlate data across different stages of syscalls.

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. **Happy coding!**