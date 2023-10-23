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
            print("Uknow event")


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