package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

// need to save the previous instructions to go back and look for the syscall ID
const previousInstructionsBufferSize = 15

// wrapper for each findSyscallID by arch
func findSyscallID(arch specs.Arch, previouInstructions []string, curPos int) (int, error) {
	var i int
	var err error

	switch arch {
	case specs.ArchX86_64:
		i, err = findSyscallIDx86_64(previouInstructions, curPos)
	case specs.ArchX86:
		i, err = findSyscallIDx86(previouInstructions, curPos)
	case specs.ArchARM:
		i, err = findSyscallIDARM(previouInstructions, curPos)
	default:
		log.Fatalln(arch, "is not supported")
	}

	return i, err
}

// findSyscallIDx86_64 goes back from the call until it finds an instruction with the format
// MOVQ $ID, 0(SP), which is the one that pushes the syscall ID onto the base address
// at the SP register
func findSyscallIDx86_64(previouInstructions []string, curPos int) (int, error) {
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

// findSyscallIDx86 goes back from the call until it finds an instruction with the format
// MOVL $ID, 0(SP), which is the one that pushes the syscall ID onto the base address
// at the SP register
func findSyscallIDx86(previouInstructions []string, curPos int) (int, error) {
	i := 0

	for i < previousInstructionsBufferSize {
		instruction := previouInstructions[curPos%previousInstructionsBufferSize]

		isMOVL := strings.Index(instruction, "MOVL") != -1
		isBaseSPAddress := strings.Index(instruction, ", 0(SP)") != -1

		if isMOVL && isBaseSPAddress {
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

func findSyscallIDARM(previouInstructions []string, curPos int) (int, error) {
	i := 0

	for i < previousInstructionsBufferSize {
		instruction := previouInstructions[curPos%previousInstructionsBufferSize]

		isMOVW := strings.Index(instruction, "MOVW") != -1
		isBaseSPAddress := strings.Index(instruction, ", R0") != -1
		// fmt.Println("isMOVW : ", isMOVW, "isBaseSPAddress : ", isBaseSPAddress)
		syscallIDBeginning := strings.Index(instruction, "$")
		if isMOVW && isBaseSPAddress && (syscallIDBeginning != -1) {
			// if (syscallIDBeginning == -1 ){
			// 	return -1, fmt.Errorf("Failed to find syscall ID on line: %v", instruction)
			// }
			syscallIDEnd := strings.Index(instruction, ", R0")

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

func getSyscallList(disassambled *os.File, arch specs.Arch) []string {

	scanner := bufio.NewScanner(disassambled)

	// keep a few of the past instructions in a buffer so we can look back and find the syscall ID
	previousInstructions := make([]string, previousInstructionsBufferSize)
	lineCount := 0
	syscalls := make(map[int]bool)

	j := getCallOpByArch(arch)

	fmt.Println("Scanning disassembled binary for syscall IDs")

	for scanner.Scan() {
		instruction := scanner.Text()
		previousInstructions[lineCount%previousInstructionsBufferSize] = instruction

		if strings.Contains(instruction, j+"syscall.Syscall(SB)") || strings.Contains(instruction, j+"syscall.Syscall6(SB)") ||
			strings.Contains(instruction, j+"syscall.RawSyscall(SB)") || strings.Contains(instruction, j+"syscall.RawSyscall6(SB)") {
			id, err := findSyscallID(arch, previousInstructions, lineCount)
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
		syscallsList[i] = syscallIDtoName[arch][id]
		i++
	}

	sort.Strings(syscallsList)

	return syscallsList
}

func main() {
	flag.Parse()

	if len(flag.Args()) < 2 {
		fmt.Println("Usage: go2seccomp /path/to/binary /path/to/profile.json")
		os.Exit(1)
	}

	binaryPath := flag.Args()[0]
	profilePath := flag.Args()[1]

	f := openElf(binaryPath)

	if !isGoBinary(f) {
		fmt.Println(binaryPath, "doesn't seems to be a Go binary")
		os.Exit(1)
	}

	arch := getArch(f)

	disassambled := disassamble(binaryPath)
	defer disassambled.Close()
	defer os.Remove("disassembled.asm")

	syscallsList := getSyscallList(disassambled, arch)

	fmt.Printf("Syscalls detected (total: %v): %v\n", len(syscallsList), syscallsList)

	writeProfile(syscallsList, arch, profilePath)
}
