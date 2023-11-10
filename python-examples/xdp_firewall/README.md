# Beginner's Guide to XDP - A Journey Through Crafting XDP-Based Firewall with BCC

In my previous [article](https://www.kungfudev.com/blog/2023/10/27/ebpf-beyond-observability-modifying-syscall-behavior), we explored how eBPF enables us to modify system behavior. Continuing on that theme, we're now going to delve into XDP, focusing on how it allows us to further shape and control our system's handling of network data. We're not just observing; we're actively changing how our system works. Let's see how XDP expands our toolkit for system modification.

In this exploration, we're covering the essential elements of XDP's broad capabilities. We'll highlight the fundamental procedures and actions that enable us to interact with packets efficiently. Our aim is to gather the necessary insights to craft a simple, functional XDP application. It's about establishing a solid starting point, a foundation from which we can later expand our knowledge to XDP's more sophisticated functionalities. For the moment, let’s concentrate on what is immediately useful and attainable.

## What is XDP?

eXpress Data Path (XDP), a vital part of the eBPF suite, stands out in the Linux kernel for its specialized handling of network packets, with a focus on `incoming traffic`. It operates at the core levels of the network stack, equipping us with the tools to alter the packet flow right as they hit the network interface. The extent of control and the efficiency we gain with XDP can depend on various factors, such as hardware capabilities and network driver support, which we'll delve into as we progress.

> For outgoing packet management, or egress traffic, eBPF-enabled Traffic Control (TC) is the go-to mechanism within the Linux kernel.

Building on this foundation, XDP opens the door to accelerated packet processing by functioning directly within the network driver or, given the appropriate hardware, on the network card itself. Such agility is crucial for crafting advanced firewalls, routers, load balancers, and DDoS mitigation systems, as well as for thorough network monitoring. These applications benefit immensely from XDP's ability to bypass the heavier parts of the network stack, thus reducing the computational overhead that typically hampers packet processing speed and efficiency.

### The Advantages of Using XDP

Why choose XDP when other tools are available? The answer lies in the unique position XDP occupies within the Linux kernel. Traditional network packet processing involves several layers of the network stack, each adding its own processing time. Packets received by a network card must traverse these layers before they reach user space applications, which can introduce latency and processing overhead.

Before diving into the traditional network packet flow, it's important to note that the following is a highly simplified overview for the sake of clarity. The actual journey of a network packet is far more intricate, involving complex mechanisms like DMA, various buffer management strategies, and advanced interrupt handling techniques. For this explanation, we'll focus on the core components to provide a clear understanding of the process, while acknowledging that the full system involves many additional sophisticated operations.

1. **Packet Arrival at NIC (Network Interface Card)**:    
    - A packet arrives at the NIC from the network.
2. **NIC to Kernel Transfer**:
    - The NIC raises an interrupt to signal that a packet has been received.
    - The packet is then copied from the NIC into kernel space, typically into a buffer that is part of the socket buffer structure in the kernel.
3. **NIC Driver**:
    - The NIC driver handles the interrupt and usually transfers the packet to a ring buffer in the kernel's network stack.
4. **Kernel Network Stack Processing**:
    - The packet is processed by the protocol stack in the kernel (e.g., IP, TCP/UDP). This involves checking for errors, managing flow control, and routing.
5. **Socket Buffer**:
    - Once processed, the packet is placed in a socket buffer, waiting for the user application to read it.
6. **System Calls**:
    - The application performs a system call to read the data from the kernel space to user space.
7. **User Space Application**:
    - The application in user space processes the packet's data accordingly.

Along the packet's path, concepts like socket buffers and DMA come into play, elements I mentioned in the article '[Optimizing Large File Transfers in Linux with Go.](https://www.kungfudev.com/blog/2023/01/30/optimizing-large-file-transfer-linux-go)' They're among the many components that help data travel smoothly through a network."

**XDP**, on the other hand, intercepts packets at the earliest possible point in the network stack. This early intervention is much more efficient than processing packets with standard tools like `iptables`, which operate at a higher layer and, therefore, later in the packet processing path. With XDP, packets could be dropped or redirected before the kernel does the heavy lifting, which conserves CPU cycles and boosts performance.

Moreover, XDP's tight integration with eBPF means it can leverage eBPF's versatility and efficiency. While eBPF can be used for a variety of system call overrides and kernel-level manipulations, XDP specializes in the network packet path, bringing eBPF's power directly to bear on networking. This specialization allows for quicker decisions about packet fate, which is especially beneficial in high-throughput environments where every microsecond counts.

XDP stands out by offering a way to manage network traffic with minimal latency, providing a significant performance advantage over traditional packet processing techniques.
### What's the Earliest Intervention Point for XDP in the Network Stack?

The real-world application of XDP hinges on where the eBPF program is executed, and this is largely determined by your system's setup and hardware capabilities. Here's how it breaks down:

**Offloaded Mode (NIC Hardware)**: If you have cutting-edge network cards, you might be able to offload the eBPF program right onto the card. This is like giving your network card its own brain to process packets without bothering the CPU. However, this super-fast route requires the card to be XDP-ready for offloading.

```txt
+--------------+
|  User Space  |
+--------------+
        ^
        |
+---------------------------+
|       Kernel Space        |
|  +---------------------+  |
|  | Network Driver      |  |
|  +---------------------+  |
+---------------------------+
        ^
        |
+---------------------------+
|       Hardware            |
|     (NIC Device)          |
|  +---------------------+  |
|  | XDP Program         |  |
|  | (Load & Operate)    |  |
|  +---------------------+  |
+---------------------------+

```

**Native Mode (NIC Driver)**: For most setups, the eBPF program will work within the network driver itself. This is still pretty quick because it processes packets before they get tangled up in the network stack's web. It's good news for many since most modern network drivers are built to handle this.

```txt
+--------------+
|  User Space  |
+--------------+
        ^
        |
+---------------------------+
|       Kernel Space        |
|  +---------------------+  |
|  | Network Driver      |  |
|  | +-----------------+ |  |
|  | | XDP Program     | |  |
|  | | (Load & Operate)| |  |
|  | +-----------------+ |  |
|  +---------------------+  |
+---------------------------+
        ^
        |
+---------------------------+
|       Hardware            |
|     (NIC Device)          |
+---------------------------+

```

**Generic Mode (Linux Network Stack)**: If neither of the above options is available, XDP's Generic Mode steps in, working at a higher level in the Linux network stack. This mode serves as the universal fallback option, activating when hardware or driver-level execution isn't possible. In this mode, eBPF programs process packets after they've passed through some initial layers of the network stack, which may introduce a slight delay. However, the strength of Generic Mode lies in its inclusivity, ensuring that XDP can be implemented across a wide range of systems, even when optimal performance conditions aren't met.

```txt
+--------------+
|  User Space  |
+--------------+
        ^
        |
+---------------------------+
|       Kernel Space        |
|  +---------------------+  |
|  | Network Driver      |  |
|  +---------------------+  |
|  | +-----------------+ |  |
|  | | Linux Network   | |  |
|  | | Stack           | |  |
|  | +-----------------+ |  |
|  | | XDP Program     | |  |
|  | | (Operates Here) | |  |
|  | +-----------------+ |  |
|  +---------------------+  |
+---------------------------+
        ^
        |
+---------------------------+
|       Hardware            |
|     (NIC Device)          |
+---------------------------+
```

Each of these execution points offers different advantages, and understanding your system's compatibility with each can help you make the most of XDP.

Some XDP drivers support list:

[XDP driver support status](https://github.com/xdp-project/xdp-project/blob/master/areas/drivers/README.org#xdp-driver-support-status)
[BCC XDP driver support](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)

### Deciding Packet Fate with XDP Actions

Understanding that XDP catches packets at the earliest opportunity based on its attachment mode, we also learn that it empowers our eBPF programs to dictate what happens to each packet. Once a packet is evaluated, the program ends with an action code, a simple command that decides the packet's fate. Here's a look at these five key actions:

- **XDP_DROP**: Imagine a bouncer at the door of a club, and some guests aren't on the list. XDP_DROP is that bouncer for your network, turning away packets that don't meet your criteria. It's a fundamental tool in crafting firewalls or deflecting DDoS attacks.

- **XDP_ABORTED**: If the packet processing encounters an issue, this action is used to halt and signal a processing error. It's a warning sign, not intended for use under normal operation conditions.

- **XDP_PASS**: This action is your green light, allowing packets to proceed to the kernel's network stack. The packet could be unchanged or modified by your program, XDP_PASS smoothly transitions it back into the regular processing flow.
 
- **XDP_TX**: Ever got a return-to-sender on your mail? XDP_TX does this with network packets, sending them back out the incoming network interface. Commonly used in conjunction with packet alterations, it's a key player in scenarios like load balancing.

- **XDP_REDIRECT**: It allows a packet to bypass the usual path it would take through the Linux kernel's networking stack, enabling the packet to be sent out through a different network interface card (NIC) directly. This can be used to steer traffic dynamically, based on certain criteria, to different parts of a network. Furthermore, `XDP_REDIRECT` can also send packets to a user space socket via the `AF_XDP` address family, which is particularly useful for high-performance user space applications that need to process packets, such as custom network functions or monitoring tools. This makes `XDP_REDIRECT` a versatile action for efficient network traffic management and redirection.
  
  >  AF_XDP is an address family that is optimized for high performance packet processing.
  >  
  >  AF_XDP sockets enable the possibility for XDP programs to redirect frames to a memory buffer in a user-space application.
  >  https://www.kernel.org/doc/html/v4.18/networking/af_xdp.html

Understanding these actions is vital as they form the basic vocabulary with which your eBPF programs can manage network traffic, offering a flexible toolkit for a variety of networking applications.

### XDP Across Environments

The implementation of XDP can significantly differ depending on the network environment and the specific needs of the system. In high-performance scenarios, like data centers or enterprise networks, leveraging XDP in Native or Offloaded mode can yield substantial benefits by reducing latency and freeing up CPU cycles. For smaller setups or environments where specialized hardware is not available, Generic mode ensures that XDP can still be leveraged to improve network performance and security, albeit with some trade-offs. Understanding your environment's requirements and constraints is key to choosing the right XDP mode and unlocking the full potential of this powerful network tool.

## The experiment: Crafting a Simple SSH Firewall with XDP

With the basics of XDP in our toolkit and a grasp of its strengths, it's time to put theory into practice. We're about to build a straightforward firewall leveraging XDP. Our approach is uncomplicated: we'll create a `user-space` program that keeps a list of approved IP addresses. These addresses will be the only ones allowed to communicate with our SSH port.

Yes, we know that `iptables` could certainly get the job done, it's like the reliable workhorse of network security. Trustworthy and robust, it has powered us through many a digital challenge. Yet, the landscape of network management is ever-evolving, and with XDP, we've got a glimpse of the latest model, sleek and full of potential. It's time to put theory into gear and see what this new tool can do. `iptables` will always be revered for its service, but for now, we're gearing up with XDP, eager to apply our fresh insights and experience the advancements in action.
### Kernel space

We'll start by examining the `C` code of **our eBPF program** first.

We're venturing into slightly more complex territory with our `C` code this time around. While I'm no `C` expert, I'll do my best to break it down and explain each part as clearly as possible. We'll take it step by step, examining some piece of the code in detail. By the end, we'll stitch it all together to unveil the full functionality. So, let's tackle this piece by piece, and I'll share my understanding of how it all works.

```c
int xdp_firewall(struct xdp_md *ctx)
{
	// Cast the numerical addresses to pointers for packet data access
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	...
}
```

In our XDP function, the `xdp_md` structure gives us vital details to handle network packets in their raw form. It includes `data`, which is the starting point of the packet in memory, and `data_end`, which signifies the end. These elements are cast into pointers, a process that turns mere memory addresses into direct access points to the packet's data.

Now that we've established the boundaries of the packet data, we can begin to dissect the layered structure of network headers. It's akin to peeling an onion, each layer revealing more about the packet's journey and purpose. For SSH traffic, this includes several layers of encapsulation:

```
+---------------------------------+ <- data (start of packet in memory)
|      Ethernet Header            |
+---------------------------------+
|         IP Header               |
+---------------------------------+
|         TCP Header              |
+---------------------------------+
|         SSH Protocol Data       |
+---------------------------------+ <- data_end (end of packet in memory)

```

1. **Ethernet Header**: This is the first layer of encapsulation, which contains the source and destination MAC addresses and the type of payload carried.
2. **IP Header**: This header comes after the Ethernet header and contains the source and destination IP addresses, along with other fields like the `protocol` field which identifies the next level protocol, such as TCP.
3. **TCP Header**: SSH uses TCP as its transport protocol. This header follows the IP header and contains the source and destination ports, as well as other control information necessary for establishing and maintaining a TCP connection.
4. **SSH Protocol Data**: Finally, we reach the payload specific to SSH, which includes the encrypted application data for the SSH session.

In our journey through packet inspection, these layered headers are like breadcrumbs revealing the packet's path. Luckily, Linux provides us with well defined structures: `ethhdr`, `iphdr`, and `tcphdr` that we’ll utilize to craft our simple firewall. They're the tools we need to decode the packet's story and ensure only the right data passes through.

We start dissecting our packet by looking at the outermost layer: the Ethernet Header.

```c
// Define a pointer to the Ethernet header at the start of the packet data
struct ethhdr *eth = data;
// Ensure the packet includes a full Ethernet header; if not, we let it continue up the stack
if (data + sizeof(struct ethhdr) > data_end)
{
    return XDP_PASS;
}
```

In simpler terms, we’re setting a marker at the beginning of the packet to read the **Ethernet Header**. We then check to make sure the packet isn't too short—because if we don't have a complete header, we can't make any decisions, so we let it go on its way.

Next, we need to confirm if we're dealing with an IP packet. This is done by examining the protocol field within the Ethernet header.

```c
// Check if the packet's protocol indicates it's an IP packet
if (eth->h_proto != __constant_htons(ETH_P_IP))
{
	// If not IP, continue with regular packet processing
	return XDP_PASS;
}
```

In the above snippet, `eth->h_proto` is the part of the **Ethernet header** that specifies the protocol of the encapsulated data. We compare it against `ETH_P_IP`, which is the identifier for the IP protocol. The `__constant_htons()` function ensures that the protocol number is in the correct format (big-endian) for comparison. If the packet isn't an IP packet, we let it proceed up the stack with `XDP_PASS`.

Continuing in the same vein, we apply similar checks for the **IP** and **TCP** **headers**. We ensure the packet is long enough to contain these headers and use the information they provide to make further decisions.

For the IP header, we check the `protocol` field to verify if it's carrying a TCP segment. Then, we inspect the TCP header, particularly the `dest` field, to determine if the packet is headed for our specified SSH port.

Lastly, we consult an eBPF map, where we've stored a list of IP addresses that have permission to access our SSH port. By looking up the source IP address of the incoming packet (`ip->saddr`), we can decide whether to allow or block the packet based on whether it's on our list. This is the crux of our firewall logic: simple yet effective.

I've strived to keep explanations to the point, avoiding a deep dive into every line of code. However, you'll find comments within the code itself to aid understanding.


```c
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


BPF_HASH(allowed_ips, u32);

int xdp_firewall(struct xdp_md *ctx)
{
    // Cast the numerical addresses to pointers for packet data access
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Define a pointer to the Ethernet header at the start of the packet data
    struct ethhdr *eth = data;
    // Ensure the packet includes a full Ethernet header; if not, we let it continue up the stack
    if (data + sizeof(struct ethhdr) > data_end)
    {
        return XDP_PASS;
    }

    // Check if the packet's protocol indicates it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
    {
        // If not IP, continue with regular packet processing
        return XDP_PASS;
    }

    // Access the IP header positioned right after the Ethernet header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    // Ensure the packet includes the full IP header; if not, pass it up the stack
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_PASS;
    }

    // Confirm the packet uses TCP by checking the protocol field in the IP header
    if (ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    // Locate the TCP header that follows the IP header
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // Validate that the packet is long enough to include the full TCP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return XDP_PASS;
    }

    // Check if the destination port of the packet is the one we're monitoring (SSH port, typically port 22, here set as 3333 for the example)
    if (tcp->dest != __constant_htons(3333)) {
        return XDP_PASS;
    }

    // Construct the key for the lookup by using the source IP address from the IP header
    __u32 key = ip->saddr;
    // Attempt to find this key in the 'allowed_ips' map
    __u32 *value = allowed_ips.lookup(&key);
    if (value) {
        // If a matching key is found, the packet is from an allowed IP and can proceed
        bpf_trace_printk("Authorized TCP packet to ssh !\\n");
        return XDP_PASS;
    }

    // If no matching key is found, the packet is not from an allowed IP and will be dropped
    bpf_trace_printk("Unauthorized TCP packet to ssh !\\n");

    // drop packet
    return XDP_DROP;
}

```

If you're new to C like me, you might find the way we locate parts of the network packet a bit puzzling. It's a bit like using a treasure map where 'X' marks the spot, but instead of steps, we use memory addresses. This process is called pointer arithmetic, a fundamental concept in C programming that allows for navigating through memory.

Here's a breakdown of pointer arithmetic in action:

```c
struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
```

Consider this step-by-step:

1. `data` is where our packet data starts – think of it as the beginning of our treasure map.
2. `sizeof(struct ethhdr)` tells us how big the Ethernet header is, so we add this to `data` to skip past it.
3. `sizeof(struct iphdr)` tells us the size of the IP header. We add this to our current location to jump over it.

By summing these sizes, we move the pointer right to where the TCP header starts. In technical terms, each `sizeof` is the number of bytes we move forward in memory, ensuring we land at the correct spot for the TCP header.

### User space

We need to find the network device to attach our XDP program to. Each XDP program goes on one device (network interfaces) at a time. To find out which device to use, we can run the `ip addr` command. In my case, I'll attach it to `wlp5s0`. Here's how you can find your device:

```sh
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group 
	...
2: wlp5s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP 
	...
    inet 192.168.2.107/24 brd 192.168.2.255 scope global dynamic noprefixroute 
```

Just remember, your device name might be different, so replace `wlp5s0` with whatever your `ip addr` shows.

Continuing with the `Python` code for our `user-space` app, the code remains straightforward and shares similarity to our previous experiment.

```python
from bcc import BPF
import socket
import struct
import ctypes as ct


def main():
    # Load the eBPF program from the external file.
    with open("ebpf_program.c", "r") as f:
        bpf_program = f.read()

    # Load the eBPF program.
    b = BPF(text=bpf_program)
    b.attach_xdp("wlp5s0", b.load_func(
        "xdp_firewall", BPF.XDP))

    # Get the map.
    allowed_ips = b["allowed_ips"]

    # Add some IPs to the map.
    ips = ["192.168.2.37"]
    for ip in ips:
        # Convert the IP to an unsigned int using the socket library.
        # inet_aton converts the IP to a packed 32-bit binary format and unpack converts it to an unsigned int.
        unpack_ip = struct.unpack("I", socket.inet_aton(ip))[0]
        allowed_ips[ct.c_uint(unpack_ip)] = ct.c_uint(1)

    # Loop and print the output of the eBPF program.
    try:
        print("Attaching XDP program... Press Ctrl+C to exit.")
        b.trace_print()
    except KeyboardInterrupt:
        pass

    # Detach the xdp program.
    b.remove_xdp("wlp5s0")


if __name__ == '__main__':
    main()
```

Key points to note:

- We utilize `attach_xdp` to bind our XDP program to the network interface (`wlp5s0`) and `remove_xdp` to detach it, which differs from the `attach_kprobe` used for tracing kernel functions.
- The IP addresses we allow through our firewall are converted to an unsigned integer format because that's how they are stored and matched in the eBPF program.
- For those interested in the specifics of `attach_xdp`, additional details and flag options are well-documented in the [BCC reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#9-attach_xdp).

### Result

When we activate our XDP program and attempt an SSH connection from an IP address that isn't whitelisted, the terminal will display messages indicating the rejection of unauthorized access attempts. Here's how it looks when such an event is captured:

```sh
$ sudo python3 app.py

...
4 warnings generated.
Attaching XDP program... Press Ctrl+C to exit.
b' irq/127-iwlwifi-604     [002] d.s31 43104.060172: bpf_trace_printk: Unauthorized TCP packet to ssh !\\n'
b' irq/127-iwlwifi-604     [002] d.s31 43104.069012: bpf_trace_printk: Unauthorized TCP packet to ssh !\\n'
b' irq/127-iwlwifi-604     [002] d.s31 43104.073009: bpf_trace_printk: Unauthorized TCP packet to ssh !\\n'
b' irq/127-iwlwifi-604     [002] d.s31 43104.082586: bpf_trace_printk: Unauthorized TCP packet to ssh !\\n'
```

These messages are our XDP program's way of signaling that it has intercepted a connection from an unapproved source and is doing its job to protect our SSH port.

With a few lines of code and a bit of learning, we built a simple yet effective firewall using eBPF and XDP. These tools give us a lot of control and flexibility, showing just how much we can do with a little effort. We've just started exploring their potential, and there's a lot more they can do to make our networks secure and efficient.
### Determining the Mode of an Attached XDP Program

The `ip link` command can display whether an XDP program is loaded in `xdpgeneric` mode. For instance, `sudo ip link show dev [interface]` might show `xdpgeneric` if the XDP program is running in the generic mode. For native mode, it might display `xdpdrv`, and for offloaded mode, it might display `xdpoffload`.

```sh
sudo ip link show wlp5s0
3: wlp5s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 `xdpgeneric` qdisc noqueue state UP mode DORMANT group default qlen 1000
	...
    prog/xdp id 321 tag 7b2ba9ec0e8c8cae jited 
```


All the code can be found in my [repository](https://github.com/douglasmakey/ebpf-learning).
## To conclude

As we close out this introduction to eBPF and XDP, I'm really struck by how capable and flexible these tools are. Diving into this topic has been an eye-opening experience, showing just how much the Linux kernel can do. Sure, we've skipped some complex stuff and there's plenty more to learn and tricky challenges to tackle down the road. But for now, I'm thankful for what I've learned and excited for what's to come. 

Thank you for reading along. This blog is a part of my learning journey and your feedback is highly valued. There's more to explore and share regarding eBPF, so stay tuned for upcoming posts. Your insights and experiences are welcome as we learn and grow together in this domain. **Happy coding!**
