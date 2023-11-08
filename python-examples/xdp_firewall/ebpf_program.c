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
