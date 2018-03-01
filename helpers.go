package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"log"
	"os"
	"os/exec"
	"strings"
)

func openElf(filename string) *elf.File {
	bin, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		log.Fatalln("can't open file", err)
	}

	f, err := elf.NewFile(bin)
	if err != nil {
		log.Fatalln("elf read error", err)
	}

	return f
}

// Verify if the binary is a go executable.
func isGoBinary(file *elf.File) bool {

	if sect := file.Section(".gosymtab"); sect != nil {
		return true
	}

	if sect := file.Section(".note.go.buildid"); sect != nil {
		return true
	}
	return false
}

// convert debug/elf based name to specs.Arch
func getArch(file *elf.File) specs.Arch {
	var arch specs.Arch

	switch file.Machine.String() {
	case "EM_X86_64":
		arch = specs.ArchX86_64
	case "EM_386":
		arch = specs.ArchX86
	case "EM_ARM":
		arch = specs.ArchARM
	default:
		log.Fatal("Unsuported arch : " + file.Machine.String())
	}

	fmt.Println("Arch : ", arch)
	return arch
}

// write the seccomp profile to the profilePath file given an architecture and a list of syscalls (name)
func writeProfile(syscallsList []string, arch specs.Arch, profilePath string) {

	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{arch},
		Syscalls: []specs.LinuxSyscall{
			specs.LinuxSyscall{
				Names:  syscallsList,
				Action: specs.ActAllow,
			},
		},
	}

	profileFile, err := os.Create(profilePath)
	if err != nil {
		log.Fatalf("Failed to create seccomp profile: %v", err)
	}
	defer profileFile.Close()

	enc := json.NewEncoder(profileFile)
	enc.SetIndent("", "    ")
	enc.Encode(profile)
	fmt.Printf("Saved seccomp profile at %v\n", profilePath)
}

// run go tool objdump (objdump for go)
func disassamble(binaryPath string) *os.File {
	disassambled, err := os.Create("disassembled.asm")

	if err != nil {
		log.Fatalf("Failed to disassembling output file, reason: %v", err)
	}

	fmt.Printf("Using go tool objdump to disassemble %v\n", binaryPath)
	cmd := exec.Command("go", "tool", "objdump", binaryPath)
	cmd.Stdout = disassambled
	err = cmd.Run()

	if err != nil {
		log.Fatalf("Couldn't run go tool objdump: %v\n", err)
	}

	// Point to the beginning of the disassembled binary to start looking for syscalls
	disassambled.Seek(0, 0)
	return disassambled
}

func getCallOpByArch(arch specs.Arch) string {
	var j string

	switch arch {
	case specs.ArchX86_64, specs.ArchX86:
		j = "CALL "
	case specs.ArchARM:
		j = "BL "
	default:
		log.Fatalln("Arch not suppported")
	}

	return j
}

func parseFunctionName(instruction string) string {
	texts := strings.Split(instruction, " ")
	currentFunction := texts[1]
	if verbose {
		fmt.Printf("Entering function %v\n", currentFunction)
	}
	return currentFunction
}

func isSyscallPkgCall(instruction string) bool {
	return strings.Contains(instruction, "CALL syscall.Syscall(SB)") || strings.Contains(instruction, "CALL syscall.Syscall6(SB)") ||
		strings.Contains(instruction, "CALL syscall.RawSyscall(SB)") || strings.Contains(instruction, "CALL syscall.RawSyscall6(SB)")
}

func isRuntimeSyscall(arch specs.Arch, instruction, currentFunction string) bool {
	// SYSCALL => x86_64, INT 0x80 => x86, SVC or SWI => ARM
	var isRuntimeSC bool
	switch arch {
	case specs.ArchX86:
		isRuntimeSC = (strings.Contains(instruction, "INT $0x80") || strings.Contains(instruction, "SYSENTER"))
	case specs.ArchX86_64:
		isRuntimeSC = strings.Contains(instruction, "SYSCALL") &&
			!strings.Contains(currentFunction, "syscall.Syscall") &&
			!strings.Contains(currentFunction, "syscall.RawSyscall")
	case specs.ArchARM:
		isRuntimeSC = strings.Contains(instruction, "SVC $0") || strings.Contains(instruction, "SWI $0")
	}
	// there are SYSCALL instructions in each of the 4 functions on the syscall package, so we ignore those
	return isRuntimeSC
}

// Got these from https://github.com/moby/moby/issues/22252
// Even if they are not found in the binary, they are needed for starting the container
func getDefaultSyscalls(arch specs.Arch) map[int64]bool {
	syscalls := make(map[int64]bool)
	switch arch {

	case specs.ArchX86_64:
		// futex
		syscalls[202] = true
		// stat
		syscalls[4] = true
		// execve
		syscalls[59] = true
	case specs.ArchX86:
		// futex
		syscalls[240] = true
		// stat
		syscalls[106] = true
		// execve
		syscalls[11] = true
	case specs.ArchARM:
		// futex
		syscalls[240] = true
		// stat
		syscalls[106] = true
		// execve
		syscalls[11] = true
	default:
		log.Fatalln(arch, "not supported")
	}

	return syscalls
}
