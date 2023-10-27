# My eBPF Journey

## Open files vigilant

Article: https://www.kungfudev.com/blog/2023/10/14/the-beginning-of-my-ebpf-journey-kprobe-bcc

Path: `python-examples/open_files_vigilant`

By running the code, we'll be able to observe the interplay between the kernel and user space as eBPF monitors file access events.

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

## Socket surveillance

Article: https://www.kungfudev.com/blog/2023/10/22/ipv4-socket-surveillance-tracing-using-kprobe-kretprobe-maps-bcc#kernel-space

Path: `python-examples/socket_surveillance`

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

## My precious secret files

Path: `python-examples/secret_files`

let's create the two secret files in the `tmp` directory.

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

