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

// need to save the previous instructions to go back and look for the syscall ID
const previousInstructionsBufferSize = 15

// findSyscallID goes back from the call until it finds an instruction with the format
// MOVQ $ID, 0(SP), which is the one that pushes the syscall ID onto the base address
// at the SP register
func findSyscallID(previouInstructions []string, curPos int) (int, error) {
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
			return int(id), nil
		}
		i++
		curPos--
	}
	return -1, fmt.Errorf("Failed to find syscall ID")
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
	syscalls := make(map[int]bool)

	fmt.Println("Scanning disassembled binary for syscall IDs")
	for scanner.Scan() {
		instruction := scanner.Text()
		previousInstructions[lineCount%previousInstructionsBufferSize] = instruction

		if strings.Contains(instruction, "CALL syscall.Syscall(SB)") || strings.Contains(instruction, "CALL syscall.Syscall(SB)") ||
			strings.Contains(instruction, "CALL syscall.RawSyscall(SB)") || strings.Contains(instruction, "CALL syscall.RawSyscall6(SB)") {
			id, err := findSyscallID(previousInstructions, lineCount)
			if err != nil {
				log.Printf("Failed to find syscall ID for line %v: %v, reason: %v\n", lineCount+1, instruction, err)
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
		syscallsList[i] = syscallIDtoName[id]
		i++
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
