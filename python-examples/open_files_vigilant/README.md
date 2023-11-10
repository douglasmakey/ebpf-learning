
# The beginning of my eBPF Journey - Kprobe Adventures with BCC

Some time ago, I read about a technology called eBPF, which allows the creation of programs that interact with the Linux kernel without the need to program kernel modules. This concept quickly piqued my interest, prompting me to delve deeper into its intricacies. For a period, I consumed various articles and watched some videos about eBPF, although I hadn’t found the opportunity or time to experiment with it hands-on. Recently, my company, Sourced, had the chance to work on a project involving eBPF. You can imagine my excitement, as I had been eager to learn about it for quite some time. So, here we are. 

This marks the inaugural post in what I anticipate will be a series documenting my eBPF learning journey.

## What is eBPF?

> eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in a privileged context such as the operating system kernel. It is used to safely and efficiently extend the capabilities of the kernel without requiring to change kernel source code or load kernel modules.
> 
> https://ebpf.io/what-is-ebpf/
> 

eBPF, which stands for Extended Berkeley Packet Filter, is an innovative technology that provides programmable hooks into the Linux kernel, enabling developers to run custom bytecode (they should be small programs with some limitations) within the `kernel space` without the need to change kernel source code or load kernel modules. Originally designed for network packet filtering, eBPF has evolved to support a range of functionalities, turning it into a versatile, in-kernel virtual machine.

eBPF programs are `event-driven`, executing when the kernel or an application traverses a specific hook point. Predefined hooks encompass system calls, function entries/exits, kernel tracepoints, network events, and several additional instances.

![[Pasted image 20231014190756.png]]

The image above depicts a `user-space` application initiating a system call to the Linux Kernel. An eBPF program is shown intercepting this call at the System Call Interface, illustrating how eBPF can monitor or alter system behavior through syscall hooking. This showcases eBPF's ability to bridge `user-space` and `kernel-space` interactions, enabling enhanced system monitoring and customization.

In the example, the hook is set for the `execve` syscall using `kprobe`, a dynamic tracing tool that allows you to intercept and inspect kernel function calls. While the hook in this scenario is specific to `execve`, it could be tailored to any other syscall associated with common tasks. For instance, opening a file involves the `open` or `openat` syscalls, while creating a new process utilizes the `clone` syscall, among others. The flexibility of `kprobe` facilitates an adaptable approach to monitoring and interacting with different kernel activities through eBPF programs.

This has been a brief, light overview of eBPF. I am omitting, and will continue to omit some complex concepts such as loader, verification, compilation, JIT, among others. If you wish to delve deeper into the benefits and other concepts, there's already a wealth of great content available that explains these much better. I recommend watching and visiting the following resources:

- [A Beginner's Guide to eBPF Programming with Go • Liz Rice](https://www.youtube.com/watch?v=uBqRv8bDroc)
- [Getting Started with eBPF - Liz Rice, Isovalent](https://www.youtube.com/watch?v=TJgxjVTZtfw)
- [https://ebpf.io](https://ebpf.io/).
- https://sysdig.com/blog/sysdig-and-falco-now-powered-by-ebpf/
- https://elinux.org/images/d/dc/Kernel-Analysis-Using-eBPF-Daniel-Thompson-Linaro.pdf
- https://isovalent.com/books/learning-ebpf/

## Program with eBPF


eBPF empowers you to interact directly with the `kernel space`, paving the way for creating cool, high-performance programs. Whether it's for networking, security, or system monitoring, the sky's the limit with eBPF. Plus, there's a rich ecosystem of existing tools and projects that cover a wide array of use cases, which you can leverage or get inspired by.


![[Pasted image 20231014202131.png]]


Getting started with eBPF programming is made easier thanks to a variety of well-maintained projects. Here are three noteworthy ones:

1. **BCC (BPF Compiler Collection)**: BCC is a framework allowing the integration of eBPF programs within Python scripts, aimed mainly at application and system profiling/tracing. It facilitates the collection and display of statistics or event data in a user-friendly format. Executing the Python script generates eBPF bytecode and loads it into the kernel, I would kickstart my eBPF programming journey with BCC due to its comprehensive toolkit, docs, examples, and supportive community.

2. **Go eBPF**: The Go eBPF library offers a streamlined approach to handling eBPF bytecode generation, and the loading and management of eBPF programs. Typically, eBPF programs are crafted in a higher-level language and then compiled into eBPF bytecode using the clang/LLVM compiler.

3. **Rust Aya**: Aya is a modern eBPF library designed to be modular and easy to use. If you prefer working with Rust, Aya could be an excellent choice for your eBPF development.

Each of these projects offers a unique environment to delve into eBPF programming, catering to different preferences and programming languages.

eBPF development typically involves crafting two distinct programs: one residing in `user space` that acts as a frontend, and the other being the eBPF program itself executing within the **eBPF virtual machine** in `kernel space`. The user space program can be written in a variety of languages such as `Python`, `Go`, `Rust`, or `C`, serving as an interface for managing and interacting with the eBPF program. On the other hand, the eBPF program, which is instrumental in interfacing with the kernel, is traditionally written in `C`.

A crucial aspect of eBPF programs is the ability to share collected information and maintain state. To serve this purpose, eBPF programs leverage `eBPF maps`, which allow the storage and retrieval of data across a variety of data structures. eBPF maps can be accessed both from eBPF programs and `user-space` applications via a system call, facilitating a robust communication between `kernel` and `user` space. This feature not only enhances data sharing capabilities but also extends the state management potential of eBPF programs, which we will explore in more detail in future posts.

## Let start

### Setting Up Local Environment on My M1 with Lima

Lima, standing for **Li**nux on **Ma**c, serves as a lightweight and flexible environment ideal for our eBPF learning journey, especially on my M1 Max. It effortlessly establishes a seamless Linux setting, enabling a safe and controlled space for experimenting with eBPF programs. If you're on an Ubuntu machine, you're already set to explore eBPF directly. However, if you prefer, you can also utilize the virtual machine platform of your choice. Lima, with its hassle-free setup, remains a superb choice for a hands-on eBPF learning experience, for Mac users.


```yml
images:
- location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
  arch: "x86_64"
- location: "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-arm64.img"
  arch: "aarch64"

mounts:
- location: "/Users/douglasmakey/workdir/personal/ebpf-learning"
  writable: true

provision:
- mode: system
  script: |
    #!/bin/bash
    apt-get update
    apt-get install -y bpfcc-tools linux-headers-$(uname -r)
    apt-get install -y build-essential pkg-config libssl-dev
```


The configuration provided above is a straightforward YAML setup to create a Lima VM running Ubuntu, along with the installation of the necessary dependencies for today's exploration. Notably, this configuration utilizes an ARM64 image to accommodate my ARM64 architecture machine.

If you wish to delve into all the configuration possibilities for Lima VM, you can visit this [resource](https://github.com/lima-vm/lima/blob/master/examples/default.yaml).

To initialize the instance, first install Lima and then create the instance using the following commands:

```bash
brew install lima
limactl start --name ubuntu ubuntu.yaml
```

After that we could check our instances:

```bash
limactl list
NAME      STATUS     SSH                VMTYPE    ARCH       CPUS    MEMORY    DISK      DIR
ubuntu    Running    127.0.0.1:64701    qemu      aarch64    4       4GiB      100GiB    ~/.lima/ubuntu
```

Now, you can access your machine using the command `limactl shell {NAME}`. For instance:

```bash
limactl shell ubuntu
...
douglasmakey@lima-ubuntu:/Users/douglasmakey $
```
### The Unforgettable Hello World: eBPF Edition

As previously mentioned, eBPF programs are event-driven. For this `Hello World` example, we'll attach a hook to the `clone` syscall and simply print `Hello World` every time the kernel triggers a `clone` call.

> The `clone` syscall in Linux is used to create a new process or thread. Unlike the more traditional `fork` syscall, which also creates a new process, `clone` allows for more fine-grained control over what is shared between the parent and child processes. For example, Docker uses the `clone` syscall to manage namespaces, allowing containers to share or isolate system resources from the host. ;)

In this hook, we'll employ a `kprobe`, which stands for `kernel probe`. A `kprobe` is a powerful mechanism in the Linux kernel that allows developers to dynamically break into any kernel routine. It's particularly handy for tracing system calls and inspecting system behavior without altering the kernel code.

```plaintext
 +-------------------+     +-------------+     +-----------------+     +-------------------+
 | User Space Program|     | Linux Kernel|     |   eBPF Program  |     |   clone syscall   |
 +-------------------+     +-------------+     +-----------------+     +-------------------+
        |                     |                     |                         |
        |                     |                     |                         |
        | Attach hook         |                     |                         |
        |-------------------->|                     |                         |
        |                     |                     |                         |
        |                     | Load eBPF Program   |                         |
        |                     |-------------------->|                         |
        |                     |                     |                         |
        |                     |                     | Attach to clone syscall |
        |                     |                     |------------------------>|
        |                     |                     |                         |
        |                     |                     |                         |
        |                     | Trigger clone call  |                         |
        |                     |-------------------->|                         |
        |                     |                     |                         |
        |                     |                     | Print "Hello World"     |
        |                     |                     |------------------------>|

```


Great! The below Python code have all the necessary components to execute our first "Hello World" eBPF program.

```python
from bcc import BPF

# Define the eBPF program as a string.
bpf_program = """
#include <uapi/linux/ptrace.h>
int syscall__clone(struct pt_regs *ctx) {
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
```

The code snippet provided below is accompanied by comments that explain the process. Three notable aspects can be highlighted from it are:

1. The `syscall__` prefix within the `C` code is a special prefix that creates a `kprobe` for the system call name provided as the remainder.
2. **`get_syscall_prefix`**: This function aims to determine the prefix for system call names, which may vary across different kernel versions and architectures.
   
   This is great because for `x86_64` and `arm64` the prefix are different for instance in `arm64` is `__arm64_sys_clone` :
   
   ```bash
   grep sys_clone /proc/kallsyms
   0000000000000000 t __do_sys_clone
   0000000000000000 T __arm64_sys_clone
   ...
   ```

3. **`attach_kprobe`**: This function is crucial for attaching the eBPF program to a specific kernel function, enabling the interception of system events at kernel level.
4. **`trace_print`**: This function serves as the conduit for printing the output from the eBPF program to the console, providing real-time feedback whenever the targeted system call is triggered.

Now, let's execute this application and observe the outcome.

```bash
sudo python3 app.py 
Attaching kprobe to sys_clone... Press Ctrl+C to exit.
b'node-12331   [003] d...1 26176.680654: bpf_trace_printk: Hello, World!'
b'sh-13469   [002] d...1 26176.687238: bpf_trace_printk: Hello, World!'
b'node-12331   [003] d...1 26176.691378: bpf_trace_printk: Hello, World!'
b'sh-13471   [002] d...1 26176.695470: bpf_trace_printk: Hello, World!'
b'node-12331   [000] d...1 26176.702436: bpf_trace_printk: Hello, World!'

```

Quite an amazing thing, isn't it? By running the app, we get to witness firsthand how the eBPF program interacts with the kernel. Although this is a simple example, it demonstrates the powerful potential that comes with the ability to attach to kernel syscalls and perform cool operations. The sky's the limit from here on, as this fundamental understanding lays the foundation for exploring more complex and impactful eBPF projects.
### Next experiment

In our next experiment, we will continue utilizing `kprobe`, for a task a little more complex and intriguing than merely printing "Hello World". Additionally, we will explore one of the methods to facilitate communication between our `user space` program and the eBPF program in `kernel space`, unveiling a more interactive aspect of eBPF programming.

In this experiment, we aim to monitor each instance of a process opening a file, akin to having a vigilant file policeman on duty. This file guardian will keep a watchful eye on file access events, logging crucial information such as the process involved, the file being accessed, and others.

To achieve this, we need to identify the syscalls invoked when a file is opened. A useful tool for this purpose is `strace`, which allows us to observe the syscalls involved when we execute a program, like when we read a file using a command such as `cat`. By employing `strace`, we can unveil the underlying syscalls.

```bash
$ strace cat ubuntu.yml
execve("/usr/bin/cat", ["cat", "ubuntu.yml"], 0xffffcffe1b28 /* 24 vars */) = 0
brk(NULL)                               = 0xaaaab796c000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffff9b115000
openat(AT_FDCWD, "ubuntu.yml", O_RDONLY) = 3
mmap(NULL, 139264, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffff9abcc000
...
```

With this info, we now know that for this experiment, we should target the hook (the `kprobe`) at the `openat` syscall, as it is the syscall associated with opening a file.
#### Kernel space

We'll start by examining the `C` code for **our kernel space app** first, as this time it's a bit more intricate with more code involved.

```c
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
```

The things to highlight from this code are:

* `BPF_PERF_OUTPUT(events);`: Creates a BPF table for pushing out custom event data to `user space` via a perf ring buffer. This is the preferred method for pushing per-event data to `user space`.
* `syscall__openat(...)` In this instance, the function accepts parameters associated with the syscall, including the file descriptor, file name, and flags. The arguments are specified in the function declaration, mirroring the parameters of the original `openat` syscall, which facilitates a direct interaction with the syscall's data. 
  
  The `__user` pointer indicates that `filename` points to a `user-space` memory.
* `bpf_probe_read_user_str()`: This function is used to safely read data from a user-space, the data is copied from `user space` to `kernel space`. It's used here to read the filename string from the `filename` pointer passed to the function.
* For a deeper understanding of some of these helper functions, like `bpf_get_current_comm` or  `bpf_get_current_uid_gid` you can refer to the [bcc documentation](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#6-bpf_get_current_comm).

#### User space our Python app

Continuing with the `Python` code for our `user space ` app, this time it's slightly different from our Hello World example as we introduce some new concepts.

```python
import os
from bcc import BPF
from time import sleep
import ctypes as ct

class EventData(ct.Structure):
    _fields_ = [
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16),  # TASK_COMM_LEN
        ("fname", ct.c_char * 255), # NAME_MAX
        ("flags", ct.c_int)
    ]

    def translate_flags(self, flags):
	    ...
        return "|".join(str_flags)

def print_event(cpu, data, size):
    e = ct.cast(data, ct.POINTER(EventData)).contents
    print(f"UID: {e.uid} COMM: {e.comm} Flags: {e.translate_flags(e.flags)} File: {e.fname}")


def main():
    # Load the eBPF program from the external file.
    with open("ebpf_program.c", "r") as f:
        bpf_program = f.read()

    # Load the eBPF program.
    b = BPF(text=bpf_program)
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'

    # Attach the kprobe defined in the eBPF program to the clone system call.
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    
    # Open a perf buffer on the 'events' map, with 'print_event' as the callback function
    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            # Poll the perf buffer for new events
            b.perf_buffer_poll()
            # Sleep for 2 seconds before polling again
            sleep(2)
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
```

The things to highlight from this code are:

- A custom data structure `EventData` is defined using `ctypes`, which mirrors the structure defined in the eBPF program. This ensures the data received from the kernel is correctly interpreted in `user space`.
- The `open_perf_buffer` function, this operates on a table defined in the BPF program as `BPF_PERF_OUTPUT()`, and associates the callback Python function to be invoked when data is available in the perf ring buffer. This setup is part of the recommended mechanism for transferring per-event data from `kernel-soace` to `user-space`, showcasing a seamless way of communication between the kernel and user space applications.
- The `perf_buffer_poll`: This method polls from all open perf ring buffers, checking for new events and triggering the associated `callback` functions to process the data. This action facilitates the continuous flow of data from the kernel to the user space, allowing for real-time monitoring and analysis.

Now it's time to bring this experiment to life by executing it inside our virtual machine. By running the code, we'll be able to observe the interplay between the `kernel` and `user` space as eBPF monitors file access events.

```bash
sudo python3 app.py 
...
UID: 501 COMM: b'node' Flags: O_RDONLY File: b'/proc/14484/cmdline'
UID: 501 COMM: b'which' Flags: O_CLOEXEC File: b'/etc/ld.so.cache'
UID: 501 COMM: b'which' Flags: O_CLOEXEC File: b'/lib/aarch64-linux-gnu/libc.so.6'
UID: 501 COMM: b'which' Flags: O_RDONLY File: b'/usr/bin/which'
UID: 501 COMM: b'sh' Flags: O_CLOEXEC File: b'/etc/ld.so.cache'
UID: 501 COMM: b'sh' Flags: O_CLOEXEC File: b'/lib/aarch64-linux-gnu/libc.so.6'
UID: 501 COMM: b'cat' Flags: O_CLOEXEC File: b'/etc/ld.so.cache'
...
```

With the output displayed, our vigilant watcher resembles Heimdall, with the ability to see everything that transpires in our system! Just like Heimdall guards the Bifröst in Norse mythology, our eBPF program stands guard over file access events, granting us insight into the system's operations. This exciting outcome demonstrates the potent capabilities of eBPF and sets the stage for more complex and insightful explorations in our upcoming posts.

All the code can be found in my [repository](https://github.com/douglasmakey/ebpf-learning).
## To Conclude 

Through our exploration, we've unveiled the basics of eBPF programming by delving into a simple "Hello World" example and then transitioning to a more complex file monitoring experiment. These exercises showcased eBPF's potential in system monitoring and interaction, paving the way for more advanced explorations. The journey from understanding syscalls, crafting eBPF programs, to witnessing real-time kernel-user space interactions, has set a solid foundation for diving deeper into the eBPF ecosystem. I acknowledge that there's much more to explain and I've omitted some complex aspects for now, but the idea is to unravel these intricacies in future posts. Whether it's for performance tuning, security monitoring, or system analysis, eBPF emerges as a powerful tool in the modern Linux kernel environment. 

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. Happy coding!