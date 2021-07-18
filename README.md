# procmon

A toy project used to play around with eBPF via [redbpf](https://github.com/foniod/redbpf).

This just captures a couple of syscalls like `connect` and `send`/`write` for a given PID
and prints some parameters they were called with.
