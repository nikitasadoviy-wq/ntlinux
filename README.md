# ntlinux

Experimental Windows NT kernel compatibility layer for Linux.

## Description

`ntlinux` is an experimental project exploring whether selected Windows
kernel-mode components (`.sys` drivers) can be analyzed and eventually
executed through a native Linux compatibility environment without running
a complete Windows kernel.

The long-term goal is to provide the NT kernel interfaces and semantics
required by supported Windows kernel-mode components.

The project is currently in the **static analysis and reverse-engineering
stage**.

```text
Windows Application / Game
          |
          v
     Windows user space
          |
          v
       ntlinux
          |
          v
      Linux kernel
Current Status

The project does not execute Windows kernel drivers yet.

The current focus is ntinspect, a PE/COFF and Windows driver analysis tool
used to investigate the structure, dependencies and code of .sys files.

ntinspect

ntinspect analyzes Windows PE images, including kernel-mode drivers.

Current capabilities:

DOS / MZ header parsing
PE signature validation
COFF header parsing
PE32 / PE32+ detection
x86-64 architecture detection
PE section parsing
Import table parsing
Export table parsing
Base relocation parsing
UTF-16LE string scanning
Windows driver profile analysis
NT kernel API import classification
x86-64 disassembly using Capstone
CALL instruction discovery
Direct CALL target calculation
Direct CALL target validation
Indirect CALL detection
x64 .pdata runtime-function parsing
Runtime function range detection
CALL-to-function association
Example

Basic analysis:

./ntinspect tests/exfat.sys

Analyze imports:

./ntinspect tests/exfat.sys --imports

Analyze runtime functions:

./ntinspect tests/exfat.sys --functions

Analyze CALL instructions:

./ntinspect tests/exfat.sys --calls --limit 20

Enable all analysis modules:

./ntinspect tests/exfat.sys --all --limit 20
Analysis Pipeline

The current analysis pipeline is:

PE / .sys file
      |
      v
   PE parser
      |
      +-- sections
      +-- imports
      +-- exports
      +-- relocations
      +-- strings
      +-- driver profile
      |
      v
   NT ABI analysis
      |
      v
   .pdata parsing
      |
      v
 runtime functions
      |
      v
 x86-64 disassembly
      |
      v
   CALL analysis
      |
      v
 function relationships
      |
      v
      IAT
      |
      v
 imported NT APIs
Runtime Function Analysis

On x86-64 Windows PE images, .pdata contains runtime-function information.

ntinspect reads the runtime-function table and extracts:

function start RVA
function end RVA
unwind information
function size

These ranges are then used by CALL analysis so that executable code can be
analyzed within known function boundaries instead of blindly disassembling
an entire executable section.

For example:

Function 1
0x000010AC - 0x000014E1

    0x000014BB
        CALL -> 0x00001008
CALL Analysis

ntinspect currently distinguishes:

Direct CALL
E8 xx xx xx xx

The target is calculated from the x86-64 relative displacement.

Example:

0x000014BB  CALL -> 0x00001008 [direct] [exec]
Indirect CALL

Examples include:

call rax
call [rax]
call qword ptr [rip + disp32]

These are currently reported as indirect calls.

Future analysis will resolve RIP-relative indirect calls through the PE
Import Address Table (IAT).

Target output:

0x00001094  CALL -> ntoskrnl.exe!IofCallDriver
Project Structure
ntlinux/
├── src/
│   ├── ntinspect.c
│   ├── pe_utils.c
│   ├── pe_sections.c
│   ├── pe_imports.c
│   ├── pe_exports.c
│   ├── pe_relocs.c
│   ├── pe_strings.c
│   ├── pe_driver.c
│   ├── pe_abi.c
│   ├── pe_functions.c
│   ├── disasm_x64.c
│   └── calls.c
│
├── include/
│   ├── pe.h
│   ├── pe_utils.h
│   ├── pe_sections.h
│   ├── pe_imports.h
│   ├── pe_exports.h
│   ├── pe_relocs.h
│   ├── pe_strings.h
│   ├── pe_driver.h
│   ├── pe_abi.h
│   ├── pe_functions.h
│   ├── disasm_x64.h
│   └── calls.h
│
├── tests/
│   ├── exfat.sys
│   └── battc.sys
│
├── docs/
├── Makefile
├── README.md
└── TODO.md
Building

Dependencies:

GCC
GNU Make
Capstone development library

Build:

make

Clean:

make clean

Rebuild:

make rebuild
Development Roadmap
Phase 1 — PE Analysis
 DOS header parser
 PE header parser
 Section parser
 Import parser
 Export parser
 Relocation parser
 String scanner
 Driver profile
 NT ABI import classification
Phase 2 — Code Analysis
 x86-64 disassembly
 Executable section detection
 CALL discovery
 Direct CALL target calculation
 Direct CALL target validation
 .pdata runtime-function parsing
 CALL-to-function association
 IAT-aware indirect CALL resolution
 Function name discovery
 Basic block detection
 Control-flow graph
 Function call graph
 Cross-reference analysis
Phase 3 — NT ABI Model
 NT types
 NT status codes
 Object manager model
 Memory manager model
 I/O manager model
 IRP model
 Synchronization primitives
 Registry model
 Process/thread model
 Security model
 PnP model
 Power management model
 WMI / ETW interfaces
Phase 4 — Driver Runtime
 PE image loader
 Relocation application
 Import resolution
 Driver initialization model
 Driver object model
 Device object model
 IRP dispatch
 NT-to-Linux kernel mapping
 Driver isolation
Phase 5 — Compatibility Testing
simple test driver
        |
        v
toy WDM driver
        |
        v
filesystem driver
        |
        v
security-related driver
        |
        v
complex third-party driver

Only drivers compatible with the implemented NT ABI should be considered for
runtime testing.

Design Principles
No Windows kernel

ntlinux aims to implement the NT interfaces and semantics required by
supported drivers instead of embedding or booting a complete Windows kernel.

Linux-native backend

Linux remains the host kernel.

NT concepts are mapped onto Linux primitives where practical.

Analysis before execution

A .sys file should be statically analyzed before any attempt at runtime
loading or execution.

Isolation

Kernel-mode code is inherently privileged. Any future runtime must prioritize
validation, isolation and controlled execution.

Current Limitations

ntlinux is currently an analysis project.

It cannot execute arbitrary Windows .sys drivers.

Static analysis also cannot perfectly recover all program behavior because
optimized native code may contain indirect control flow, embedded data,
runtime-generated addresses and other constructs that require deeper analysis.

Why?

Modern Windows software can depend on kernel-mode components.

A compatibility environment implementing only Win32/user-mode interfaces
cannot provide compatibility with kernel-mode software.

ntlinux explores what would be required to bridge selected Windows NT
kernel interfaces to a Linux-native implementation.

License

ntlinux is licensed under the GNU General Public License v3.0.
