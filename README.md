# Living in the Namespace

A minimal C persistence tool demonstrating how to:

- Join live namespaces (user, pid, net, mnt, ipc, uts, cgroup) via `/proc/*/ns/*` and `setns()`
- Elevate privileges inside a user namespace `unshare(CLONE_NEWUSER)` + `UID/GID mapping`
- Daemonize using (`fork()`, `setsid()`, `prctl(PR_SET_NAME)`, redirect stdio to `/dev/null`)
- Beacon in-memory over a local HTTP channel `127.0.0.1:8443` with randomized intervals
- Self-delete in-memory by zeroing and unlinking the running binary via `/proc/self/exe` (Optional)

## Build
```bash
gcc -O2 -o unshare_persistence unshare_persistence.c
```
## Usage 
```bash
sudo ./unshare_persistence # easy jus run it
```

### Full Details
For a complete explanation of this technique see my blog post:

[Blog post](https://hackmd.io/@0xmadvise/rJPLNLRwlx)
