# Beyond Observability - Modifying Syscall Behavior with eBPF - My Precious Secret Files

In my previous two articles, we explored eBPF and its capability in employing probes within kernel-space. Through our journey in our experiments [Open files vigilant](https://www.kungfudev.com/blog/2023/10/14/the-beginning-of-my-ebpf-journey-kprobe-bcc) and [Socket surveillance](https://www.kungfudev.com/blog/2023/10/22/ipv4-socket-surveillance-tracing-using-kprobe-kretprobe-maps-bcc), we merely scratched the surface of eBPF's observability capabilities without altering the behavior of syscalls. Now, as we venture further, we'll delve into how we can not only observe but also influence syscall behavior using eBPF.

eBPF extends beyond mere observability, empowering us to actively modify syscall behavior, thus opening a gateway to a more interactive and controlled system interaction.
## The eBPF helpers

eBPF helpers are predefined functions provided by the kernel, facilitating interaction between eBPF programs and the kernel. They offer a controlled access to the kernel's internal data and functions, allowing us to read or modify data related to syscalls and other kernel operations.

These helpers are instrumental in modifying syscall behavior, enabling eBPF programs to alter data associated with syscalls, change their return values, or even redirect network packets. Through eBPF helpers, we can actively influence the system's behavior, extending eBPF's capabilities beyond mere observability to a more interactive and controlled system interaction.

> These helpers are used by eBPF programs to interact with the system, or with the context in which they work. For instance, they can be used to print debugging messages, to get the time since the system was booted, to interact with eBPF maps, or to manipulate network packets. Since there are several eBPF program types, and that they do not run in the same context, each program type can only call a subset of those helpers.
> 
> https://man7.org/linux/man-pages/man7/bpf-helpers.7.html


In today's experiment, we are set to delve into the practical utilization of two distinct yet powerful eBPF helpers: `bpf_override_return` and `bpf_send_signal`. 

The `bpf_override_return` helper is instrumental in altering the return values of syscalls, providing us with the ability to manipulate system interactions based on custom logic. On the other hand, `bpf_send_signal` offers a pathway to send signals to the process of the current task. Together, these helpers not only illustrate the flexibility and control afforded by eBPF but also set the stage for a deeper exploration into modifying syscall behavior for real-world applications. Through this experiment, we aim to showcase the profound impact these helpers can have on system behavior and the broader implications for eBPF-driven development.

> Special attention to **bpf_override_return**:
> 
> This helper has security implications, and thus is subject to restrictions. It is only available if the kernel was compiled with the **CONFIG_BPF_KPROBE_OVERRIDE** configuration option, and in this case it only works on functions tagged with **ALLOW_ERROR_INJECTION** in the kernel code.
> [Source.](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html#:~:text=of%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20failure.%0A%0A%20%20%20%20%20%20%20long-,bpf_override_return,-(struct%20pt_regs%20*)

## The experiment: My precious secret files

Imagine crafting a program to safeguard our valued secret files, leveraging the full range of eBPF capabilities. Our focus will be on intercepting the `openat` syscall, a familiar entity from previous explorations. Whenever an attempt is made to access our secret files through this syscall, we will step in to alter its behavior, ensuring our files remain under tight lock and key.

We will design a two-tier security mechanism for our files. With security `level 1`, the modified behavior of the syscall will result in returning an `EACCES` error to the caller, signifying access denial. On escalating to security `level 2` or higher, the measures become more strict; a SIGKILL signal is dispatched to terminate the program attempting to access our precious files, ensuring an uncompromising safeguard against unauthorized access.

In order to identify which files are to be safeguarded as our secret files, we require a medium to relay this information from our `user-space` to the `kernel-space`. For this purpose, we'll employ an eBPF map to accomplish this task:

If you've read my previous article, you're already familiar with one of the ideal use case of eBPF maps serving as a conduit for data exchange between the kernel and user spaces.


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

With this setup, we can have our `user-space` application manage a list of secret files and share this list with the `kernel-space` via a map. The eBPF program residing in the `kernel-space` will merely check if the file being attempted to open is listed in the map, and if so, alter the behavior accordingly. This scheme provides a streamlined way for `user-space` and `kernel-space` to interact and make informed decisions based on shared data.
### Kernel space

We'll start by examining the `C` code **our kernel space app** first.

The `C` code presented is straightforward, with each segment being simple and previously explained. However, this time, the spotlight falls on the eBPF map, showcasing a method to manage more complex data relationships within eBPF programs.

```c
// Define a key structure to hold the file name
struct key_t {
  char fname[NAME_MAX];
};

// Map to store secret files and their associated security levels
BPF_HASH(secret_files, struct key_t, int);
```

In the snippet above, a custom struct `key_t` is used as the key type for the eBPF map `secret_files`, allowing for a more organized way to handle complex keys. This struct holds the file name, which is mapped to an integer representing the security level of the file in the `secret_files` map. This approach not only enhances data organization but also facilitates handling of multi-dimensional data in eBPF programs, showcasing a method to manage sophisticated data relationships using eBPF maps.

```c
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
```

Apart from the map, the notable aspects in the above code are the utilization of `bpf_override_return` and `bpf_send_signal`, which we have discussed earlier.

The `bpf_send_signal(u32 sig)` send signal `_sig_` to the thread corresponding to the current task. The signal may be delivered to any of this process's threads. If you want to send the signal to the specific thread corresponding to the current task use `bpf_send_signal_thread(u32 sig)`

The `bpf_override_return(struct pt_regs regs, u64 rc)` Used for error injection, this helper override the return value of the probed function in this case our `openat` syscall.

### User space

Continuing with the `Python` code for our `user-space` app, the code remains straightforward and shares similarity to our previous experiment.

```python
from bcc import BPF
import ctypes as ct

# Helper function to add a secret file to the map
def add_secret_file(map, file):
    key = map.Key()
    key.fname = file[0].encode()
    value = ct.c_int(file[1])
    # Update the map with the new entry
    map[key] = value


def main():
    # Read BPF Program
    with open("ebpf_program.c") as f:
        bpf_program = f.read()

    # Load BPF program
    b = BPF(text=bpf_program)

    # Attach the kprobe defined in the eBPF program to the clone system call.
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")

    # Get thee map
    secret_files = b.get_table("secret_files")

    # Add the secret files to the map
    for file in [("/tmp/secret.txt", 1), ("/tmp/ultra_secret.txt", 2)]:
        add_secret_file(secret_files, file)

    try:
        print("Attaching kprobe to sys_openat... Press Ctrl+C to exit.")
        b.trace_print()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

```

In the provided script, the focus is drawn towards obtaining the map and adding entries to it. After loading the eBPF program, the script retrieves the eBPF map `secret_files` using `b.get_table("secret_files")`. Following this, a loop iterates through a list of secret files, each represented as a tuple containing a file path and an associated security level. The `add_secret_file` function is called with the map and each file tuple as arguments, wherein a new entry is created in the map with the file name as the key and the security level as the value. 

This encapsulates the process of dynamically updating the eBPF map with secret file entries, illustrating a straightforward mechanism to interact with and modify the eBPF map from user space.
### Result

To give our new program a spin, let's create the two secret files in the `tmp` directory.

```bash
echo "www.kungfudev.com" > /tmp/secret.txt
echo "www.kungfudev.com" > /tmp/ultra_secret.txt
```

Upon running our program with the command `sudo python3 app.py` and attempting to open the recently created files, we should observe some output. Keep in mind that `secret.txt` is assigned a security level of 1, while `ultra_secret.txt` has a level of 2. Hence, we should see the following output:

```bash
$ cat /tmp/secret.txt 
cat: /tmp/secret.txt: Permission denied

$ cat /tmp/ultra_secret.txt 
Killed

# Since we added a root user validation in our eBPF program, we can open the file as root.
$ sudo cat /tmp/ultra_secret.txt 
www.kungfudev.com
```

All the code can be found in my [repository](https://github.com/douglasmakey/ebpf-learning).
## To conclude

Through this simple example, we've illustrated that eBPF extends beyond observability, showcasing its ability to alter system call behavior, thereby highlighting its versatility and powerful impact on system-level interactions.

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. **Happy coding!**