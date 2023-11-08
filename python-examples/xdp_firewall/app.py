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
