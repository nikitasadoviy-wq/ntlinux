# ntlinux

Experimental Windows NT kernel compatibility layer for Linux.

Description

ntlinux is a project aimed at running Windows kernel-mode components on Linux by providing a compatibility layer for Windows NT kernel interfaces and driver execution.

The long-term goal is to allow supported Windows applications and games that depend on Windows kernel drivers to work on Linux without requiring a Windows installation.

The project is currently in the analysis stage. The first part focuses on analyzing Windows PE/COFF kernel drivers and understanding the NT kernel APIs they use.

Goal

The intended architecture:


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
```

The final system should be able to:

* Load Windows `.sys` drivers
* Resolve PE imports and relocations
* Provide required NT kernel APIs
* Provide Windows driver objects and I/O mechanisms
* Translate NT kernel operations to Linux equivalents
* Support Windows kernel-mode components without modifying the original driver

Current Features

`ntinspect` currently supports:

* DOS header parsing
* PE header parsing
* COFF header parsing
* PE32 and PE32+ detection
* x86-64 architecture detection
* PE section parsing
* Import table parsing
* Export table parsing
* Base relocation parsing
* UTF-16LE string detection
* Windows driver profile analysis
* NT kernel API import classification
* Executable section detection
* x86-64 disassembly using Capstone
* CALL instruction detection
* Direct CALL target calculation
* Indirect CALL detection

Analysis Pipeline

```text
Windows .sys driver
        |
        v
    PE parser
        |
        +-- Headers
        +-- Sections
        +-- Imports
        +-- Exports
        +-- Relocations
        +-- Strings
        |
        v
    ABI analysis
        |
        v
 x86-64 disassembly
        |
        v
   CALL analysis
        |
        v
 Function discovery
        |
        v
 Control-flow analysis
        |
        v
   NT ABI model
        |
        v
 Driver runtime
        |
        v
 Linux kernel
```

TODO

PE Analysis

* [x] DOS header
* [x] PE header
* [x] COFF header
* [x] Section parsing
* [x] Import parsing
* [x] Export parsing
* [x] Relocation parsing
* [x] UTF-16LE string detection

Code Analysis

* [x] x86-64 disassembly
* [x] Executable section detection
* [x] CALL instruction detection
* [x] Direct CALL target calculation
* [ ] Direct CALL target validation
* [ ] RIP-relative indirect CALL resolution
* [ ] Import/thunk CALL resolution
* [ ] Function discovery
* [ ] `.pdata` / `RUNTIME_FUNCTION` parsing
* [ ] Basic block detection
* [ ] Control-flow graph
* [ ] Call graph

NT ABI

* [ ] NT status codes
* [ ] NT data types
* [ ] Object Manager
* [ ] Memory Manager
* [ ] I/O Manager
* [ ] IRP model
* [ ] Synchronization primitives
* [ ] Registry interface
* [ ] Process and thread interfaces
* [ ] Security interfaces
* [ ] Plug and Play
* [ ] Power management
* [ ] WMI / ETW

Driver Runtime

* [ ] Windows driver loader
* [ ] PE image loading
* [ ] Import resolution
* [ ] Relocation handling
* [ ] Driver initialization
* [ ] Driver/device objects
* [ ] IRP dispatch
* [ ] NT-to-Linux API mapping
* [ ] Driver isolation

Compatibility

* [ ] Test with simple Windows drivers
* [ ] Test with filesystem drivers
* [ ] Test with user-mode/kernel-mode interaction
* [ ] Test compatibility with real applications
* [ ] Test compatibility with games

Project Status

The project is currently in early development.

At the moment, `ntlinux` does not execute Windows kernel drivers. The current implementation is a static PE and Windows driver analysis tool.

Build

Dependencies:

* GCC
* GNU Make
* Capstone

Build:


make
```

Clean:


make clean
```

Rebuild:

make rebuild
```

Usage

./ntinspect tests/exfat.sys
```

Project Structure


ntlinux/
├── src/
├── include/
├── tests/
├── docs/
├── Makefile
├── LICENSE
├── README.md
└── .gitignore
```
License

ntlinux is licensed under the GNU General Public License v3.0.
