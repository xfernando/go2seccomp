package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// TODO add a verbose flag and do a proper verbose mode
var verbose = false

// need to save the previous instructions to go back and look for the syscall ID
// have found MOVs to 0(SP) as far as 10 instructions behind, so 15 seems like a safe number
const previousInstructionsBufferSize = 15

// findSyscallID goes back from the call until it finds an instruction with the format
// MOVQ $ID, 0(SP), which is the one that pushes the syscall ID onto the base address
// at the SP register
func findSyscallID(previouInstructions []string, curPos int) (int64, error) {
	i := 0

	for i < previousInstructionsBufferSize {
		instruction := previouInstructions[curPos%previousInstructionsBufferSize]

		isMOVQ := strings.Index(instruction, "MOVQ") != -1
		isBaseSPAddress := strings.Index(instruction, ", 0(SP)") != -1

		if isMOVQ && isBaseSPAddress {
			syscallIDBeginning := strings.Index(instruction, "$")
			if syscallIDBeginning == -1 {
				return -1, fmt.Errorf("Failed to find syscall ID on line: %v", instruction)
			}
			syscallIDEnd := strings.Index(instruction, ", 0(SP)")

			hex := instruction[syscallIDBeginning+1 : syscallIDEnd]
			id, err := strconv.ParseInt(hex, 0, 64)

			if err != nil {
				return -1, fmt.Errorf("Error parsing hex id: %v", err)
			}
			return id, nil
		}
		i++
		curPos--
	}
	return -1, fmt.Errorf("Failed to find syscall ID")
}

func findRuntimeSyscallID(previouInstructions []string, curPos int) (int64, error) {
	i := 0

	for i < previousInstructionsBufferSize {
		instruction := previouInstructions[curPos%previousInstructionsBufferSize]
		isMOV := strings.Index(instruction, "MOV") != -1
		isAXRegister := strings.Index(instruction, ", AX") != -1

		// runtime·read on syscall/sys_linux_amd64.s has the following for calling the read syscall:
		// MOVL $0, AX
		// SYSCALL
		// However, some compiler optmization changes it to:
		// XORL AX, AX
		// which must be faster to zero the register than using a MOV, so we need to account for this
		isRead := strings.Index(instruction, "XOR") != -1 && strings.Index(instruction, " AX, AX") != -1
		if isRead {
			return 0, nil
		}

		if isMOV && isAXRegister {
			syscallIDBeginning := strings.Index(instruction, "$")
			if syscallIDBeginning == -1 {
				return -1, fmt.Errorf("Failed to find syscall ID on line: %v", instruction)
			}
			syscallIDEnd := strings.Index(instruction, ", AX")

			hex := instruction[syscallIDBeginning+1 : syscallIDEnd]
			id, err := strconv.ParseInt(hex, 0, 64)

			if err != nil {
				return -1, fmt.Errorf("Error parsing hex id: %v", err)
			}
			return id, nil
		}
		i++
		curPos--
	}
	return -1, fmt.Errorf("Failed to find syscall ID")
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

func isRuntimeSyscall(instruction, currentFunction string) bool {
	// there are SYSCALL instructions in each of the 4 functions on the syscall package, so we ignore those
	return strings.Contains(instruction, "SYSCALL") && !strings.Contains(currentFunction, "syscall.Syscall") &&
		!strings.Contains(currentFunction, "syscall.RawSyscall")
}

// Got these from https://github.com/moby/moby/issues/22252
// Even if they are not found in the binary, they are needed for starting the container
func getDefaultSyscalls() map[int64]bool {
	syscalls := make(map[int64]bool)
	// futex
	syscalls[202] = true
	// stat
	syscalls[4] = true
	// execve
	syscalls[59] = true

	return syscalls
}

func main() {
	flag.Parse()

	if len(flag.Args()) < 2 {
		fmt.Println("Usage: go2seccomp /path/to/binary /path/to/profile.json")
		os.Exit(1)
	}
	binaryPath := flag.Args()[0]
	profilePath := flag.Args()[1]
	disassambled, err := os.Create("disassembled.asm")
	if err != nil {
		log.Fatalf("Failed to disassembling output file, reason: %v", err)
	}
	defer disassambled.Close()
	defer os.Remove("disassembled.asm")

	fmt.Printf("Using go tool objdump to disassemble %v\n", binaryPath)
	cmd := exec.Command("go", "tool", "objdump", binaryPath)
	cmd.Stdout = disassambled
	err = cmd.Run()
	if err != nil {
		log.Fatalf("Couldn't run go tool objdump: %v\n", err)
	}

	// Point to the beginning of the disassembled binary to start looking for syscalls
	disassambled.Seek(0, 0)

	scanner := bufio.NewScanner(disassambled)
	// keep a few of the past instructions in a buffer so we can look back and find the syscall ID
	previousInstructions := make([]string, previousInstructionsBufferSize)
	lineCount := 0
	syscalls := getDefaultSyscalls()

	fmt.Println("Scanning disassembled binary for syscall IDs")
	currentFunction := ""
	for scanner.Scan() {
		instruction := scanner.Text()
		previousInstructions[lineCount%previousInstructionsBufferSize] = instruction

		if len(instruction) > 5 && instruction[0:4] == "TEXT" {
			currentFunction = parseFunctionName(instruction)
		}

		// function call to one of the 4 functions from the syscall package
		if isSyscallPkgCall(instruction) {
			id, err := findSyscallID(previousInstructions, lineCount)
			if err != nil {
				log.Printf("Failed to find syscall ID for line %v: %v, reason: %v\n", lineCount+1, instruction, err)
				lineCount++
				continue
			}
			syscalls[id] = true
		}
		// the runtime package doesn't use the functions on the syscall package, instead it uses SYSCALL directly
		if isRuntimeSyscall(instruction, currentFunction) {
			id, err := findRuntimeSyscallID(previousInstructions, lineCount)
			if err != nil {
				log.Printf("Failed to find syscall ID for line %v: \n\t%v\n\treason: %v\n", lineCount+1, instruction, err)
				lineCount++
				continue
			}
			syscalls[id] = true
		}
		lineCount++
	}

	syscallsList := make([]string, len(syscalls))
	i := 0
	for id := range syscalls {
		name, ok := syscallIDtoName[id]
		if !ok {
			fmt.Printf("Sycall ID %v not available on the ID->name map\n", id)
		} else {
			syscallsList[i] = name
			i++
		}
	}
	sort.Strings(syscallsList)
	fmt.Printf("Syscalls detected (total: %v): %v\n", len(syscalls), syscallsList)

	profile := specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64},
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
