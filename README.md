# go2seccomp

`go2seccomp` analyzes compiled go binaries and generates a seccomp profile that blocks all syscalls, except the ones
used by the binary.

It relies on a `go tool objdump` to decompile the binary. With the decompiled binary we look for the occurences of
`CALL syscall.Syscall(SB)`, `CALL syscall.Syscall6(SB)`, `CALL syscall.RawSyscall(SB)` and `CALL syscall.RawSyscall6(SB)`,
then goes back through the previous instructions searching for a `MOVQ` instruction putting the syscall ID at the base 
address pointed by the `SP` register.

Then we decode the value at the `MOVQ` instruction and save them for generating the seccomp profile json.

## Installation

`go get -u github.com/xfernando/go2seccomp`

## Usage

`go2seccomp /path/to/binary /path/to/profile.json`

## Example

Running `go2seccomp` on the `kubectl` 1.9.0 binary yields the following profile:

```json
{
    "defaultAction": "SCMP_ACT_KILL",
    "architectures": [
        "SCMP_ARCH_X86_64"
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "bind",
                "chdir",
                "chroot",
                "clone",
                "close",
                "connect",
                "dup",
                "dup2",
                "execve",
                "exit",
                "exit_group",
                "fchdir",
                "fchmod",
                "fchown",
                "fcntl",
                "fstat",
                "fsync",
                "ftruncate",
                "getcwd",
                "getdents64",
                "getgid",
                "getpeername",
                "getpid",
                "getppid",
                "getrandom",
                "getsockname",
                "getuid",
                "ioctl",
                "kill",
                "listen",
                "lseek",
                "lstat",
                "mkdirat",
                "mount",
                "munmap",
                "pipe",
                "pipe2",
                "prctl",
                "ptrace",
                "read",
                "recvmsg",
                "sendmsg",
                "setgid",
                "setgroups",
                "setpgid",
                "setsid",
                "setuid",
                "shutdown",
                "socket",
                "stat",
                "symlinkat",
                "unlinkat",
                "unshare",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

## Limitations

This will only detect simple usages of syscalls, mainly those that go through go's syscall package
and that are not using constant values.

More details about limitations can be seen at @jessfraz [keynote at FOSDEM](https://www.youtube.com/watch?v=7mzbIOtcIaQ)
around 30 minutes in.