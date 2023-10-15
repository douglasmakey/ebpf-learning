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
        str_flags = []
        if self.flags == 0:
            str_flags.append("O_RDONLY")
        else:
            if self.flags & os.O_RDONLY:    str_flags.append("O_RDONLY")
            if self.flags & os.O_WRONLY:    str_flags.append("O_WRONLY")
            if self.flags & os.O_RDWR:      str_flags.append("O_RDWR")
            if self.flags & os.O_CREAT:     str_flags.append("O_CREAT")
            if self.flags & os.O_EXCL:      str_flags.append("O_EXCL")
            if self.flags & os.O_NOCTTY:    str_flags.append("O_NOCTTY")
            if self.flags & os.O_TRUNC:     str_flags.append("O_TRUNC")
            if self.flags & os.O_APPEND:    str_flags.append("O_APPEND")
            if self.flags & os.O_NONBLOCK:  str_flags.append("O_NONBLOCK")
            if self.flags & os.O_DSYNC:     str_flags.append("O_DSYNC")
            if self.flags & os.O_ASYNC:     str_flags.append("O_ASYNC")
            if self.flags & os.O_FSYNC:     str_flags.append("O_FSYNC")
            if self.flags & os.O_SYNC:      str_flags.append("O_SYNC")
            if self.flags & os.O_CLOEXEC:   str_flags.append("O_CLOEXEC")

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