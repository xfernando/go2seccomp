# go2seccomp

`go2seccomp` analyzes compiled go binaries and generates a seccomp profile that blocks all syscalls, except the ones
used by the binary. The profile can then be used when running the binary in a container using docker, rkt, or any runtime
that supports seccomp to further reduce the container's attack surface.

This tool aims to help make the process of creating seccomp profiles for go programs easier, and can also help
developers see when changes increase or decrease the scope of what their programs can do with relation to syscalls.

## Installation

`go get -u github.com/xfernando/go2seccomp`

## Usage

`go2seccomp /path/to/binary /path/to/profile.json`

## Examples

Running `go2seccomp` on a simple hello world application like this one:

```go
package main

import "fmt"

func main() {
        fmt.Println("Hello World!")
}
```

yields this profile:

```json
 {
     "defaultAction": "SCMP_ACT_ERRNO",
     "architectures": [
         "SCMP_ARCH_X86_64"
     ],
     "syscalls": [
         {
             "names": [
                 "arch_prctl",
                 "brk",
                 "clone",
                 "close",
                 "epoll_create",
                 "epoll_create1",
                 "epoll_ctl",
                 "epoll_wait",
                 "execve",
                 "exit",
                 "exit_group",
                 "fcntl",
                 "futex",
                 "getpid",
                 "gettid",
                 "kill",
                 "madvise",
                 "mincore",
                 "mmap",
                 "munmap",
                 "open",
                 "pselect6",
                 "read",
                 "readlinkat",
                 "rt_sigaction",
                 "rt_sigprocmask",
                 "rt_sigreturn",
                 "sched_getaffinity",
                 "sched_yield",
                 "setitimer",
                 "sigaltstack",
                 "stat",
                 "tkill",
                 "write"
             ],
             "action": "SCMP_ACT_ALLOW"
         }
     ]
 }
```

With the generated profile we can then start a docker container like this (assuming you built an image for the code above
with the tag `helloworld`):

```bash
docker run --security-opt="no-new-privileges" --security-opt="seccomp=profile.json" helloworld
```

There's a script on [examples/helloworld](./examples/helloworld) called `build-and-run.sh` that takes this hello world example,
builds the binary, generates the seccomp profile, builds the docker image and runs the image with the generated profile:

Running `go2seccomp` on the `kubectl` 1.9.0 binary yields the following profile:

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": [
        "SCMP_ARCH_X86_64"
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "arch_prctl",
                "bind",
                "brk",
                "chdir",
                "chroot",
                "clone",
                "close",
                "connect",
                "dup",
                "dup2",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_wait",
                "execve",
                "exit",
                "exit_group",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fcntl",
                "fstat",
                "fsync",
                "ftruncate",
                "futex",
                "getcwd",
                "getdents64",
                "getgid",
                "getpeername",
                "getpid",
                "getppid",
                "getrandom",
                "getsockname",
                "getsockopt",
                "gettid",
                "getuid",
                "ioctl",
                "kill",
                "listen",
                "lseek",
                "lstat",
                "madvise",
                "mincore",
                "mkdirat",
                "mmap",
                "mount",
                "munmap",
                "open",
                "openat",
                "pipe",
                "pipe2",
                "prctl",
                "pread64",
                "pselect6",
                "ptrace",
                "pwrite64",
                "read",
                "readlinkat",
                "recvfrom",
                "recvmsg",
                "renameat",
                "rt_sigaction",
                "rt_sigprocmask",
                "rt_sigreturn",
                "sched_getaffinity",
                "sched_yield",
                "sendfile",
                "sendmsg",
                "sendto",
                "setgid",
                "setgroups",
                "setitimer",
                "setpgid",
                "setsid",
                "setsockopt",
                "setuid",
                "shutdown",
                "sigaltstack",
                "socket",
                "stat",
                "symlinkat",
                "tkill",
                "unlinkat",
                "unshare",
                "wait4",
                "waitid",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

## How it works

`go2seccomp` uses`go tool objdump` to decompile the binary. With the decompiled binary we search for occurences of any of the following:

* `CALL syscall.Syscall(SB)`
* `CALL syscall.Syscall6(SB)`
* `CALL syscall.RawSyscall(SB)`
* `CALL syscall.RawSyscall6(SB)`

These are calls to functions of the same name on the [syscall](https://golang.org/pkg/syscall/) package, which are used to
provide access to the underlying syscalls using constants with the syscall ID.

After finding an occurrence of one of those calls, `go2seccomp` searches the previous instructions looking for the `MOVQ` instruction
that puts the syscall ID at the address pointed by the stack pointer (`SP`) register.

As an example, let's look at the code for the `GetCwd` func of the `syscall` package. Line [152](https://github.com/golang/go/blob/104445e3140f4468839db49a25cb0182f7923174/src/syscall/zsyscall_linux_amd64.go#L152) is where
the call to the `Syscall` func is made, shown below.

```go
r0, _, e1 := Syscall(SYS_GETCWD, uintptr(_p0), uintptr(len(buf)), 0)
```

It passes the `SYS_GETCWD` constant, which has the value 79. Below we have the dissasembled code for this line.

```asm
  zsyscall_linux_amd64.go:152   0x47b234    48c704244f000000    MOVQ $0x4f, 0(SP)
  zsyscall_linux_amd64.go:152   0x47b23c    48894c2408          MOVQ CX, 0x8(SP)
  zsyscall_linux_amd64.go:152   0x47b241    4889442410          MOVQ AX, 0x10(SP)
  zsyscall_linux_amd64.go:152   0x47b246    48c744241800000000  MOVQ $0x0, 0x18(SP)
  zsyscall_linux_amd64.go:152   0x47b24f    e81c340000          CALL syscall.Syscall(SB)
```

The value the `MOVQ` instruction is putting on the address pointed by the `SP` register is 0x4F, which is 79, the ID
of the `getcwd` syscall.

We collect all syscall IDs using this method and generate a seccomp profile json as output.

### Go Runtime syscalls

Go's `runtime` package doesn't use the functions on the `syscall` package. Instead, it has a lot of assembly code that
uses syscalls directly. The file [sys_linux_amd64.s](https://github.com/golang/go/blob/master/src/runtime/sys_linux_amd64.s) contains most of those.
The first version of `go2seccomp` didn't take those into account, so a lot of syscalls needed were missing, but are now properly accounted for.

Since it now analyzes actual `SYSCALL` calls, this removed the limitations that only those syscalls made through the `syscall` package
would be discovered. Now even syscalls made in C code through `cgo` should be discovered when analyzing static builds.

### Default syscalls

When I tried running containers with profiles `go2seccomp` generated they didn't start with different error messages at times (even the basic helloworld).
After some digging, I found this [issue](https://github.com/moby/moby/issues/22252) on the moby project, where I found that some syscalls
need to be enabled on the seccomp profile because docker needs them to start the container, even if they're not needed for the binary the container runs.

The syscalls that need to be enabled by default are:

* `execve`
* `futex`
* `stat`

## Limitations

There are some limitations in go2seccomp:

* If the syscall ID passed to the syscall functions are defined at runtime, they won't be detected
  * Though a warning will be displayed when we find a syscall whose ID can't be parsed
* If you use go plugins, syscalls from the plugins probably won't be detected

More details about limitations can be seen at @jessfraz [keynote at FOSDEM](https://www.youtube.com/watch?v=7mzbIOtcIaQ)
around 30 minutes in.
