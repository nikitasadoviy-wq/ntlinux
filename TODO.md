```md
# ntlinux TODO

## ntinspect

### CLI

- [x] `--help`
- [x] `--imports`
- [x] `--exports`
- [x] `--relocs`
- [x] `--strings`
- [x] `--abi`
- [x] `--functions`
- [x] `--disasm`
- [x] `--calls`
- [x] `--all`
- [x] `--limit`

### PE Analysis

- [x] DOS / MZ header
- [x] PE signature
- [x] COFF header
- [x] PE32 / PE32+
- [x] Section table
- [x] Imports
- [x] Exports
- [x] Base relocations
- [x] UTF-16LE strings
- [x] Driver profile
- [x] NT ABI classification

### Function Analysis

- [x] Locate `.pdata`
- [x] Parse `RUNTIME_FUNCTION`
- [x] Validate function ranges
- [x] Calculate function sizes
- [x] Associate CALLs with functions
- [ ] Parse unwind information
- [ ] Detect chained runtime-function entries
- [ ] Improve function validation

### CALL Analysis

- [x] Detect CALL instructions
- [x] Detect direct `CALL rel32`
- [x] Calculate direct targets
- [x] Validate direct targets
- [x] Detect indirect CALLs
- [ ] Distinguish indirect CALL forms
- [ ] Resolve RIP-relative CALLs
- [ ] Resolve IAT slots
- [ ] Map IAT entries to imported DLL/function
- [ ] Build function-to-function references
- [ ] Build function-to-API references

### Control Flow

- [ ] Basic blocks
- [ ] Conditional branches
- [ ] Unconditional jumps
- [ ] Function entry detection
- [ ] Function exit detection
- [ ] Cross references
- [ ] Control-flow graph
- [ ] Call graph

### Advanced Analysis

- [ ] String references
- [ ] Import references
- [ ] Export references
- [ ] Global variable references
- [ ] Switch/jump-table detection
- [ ] Tail-call detection
- [ ] Indirect jump analysis
- [ ] Exception/unwind analysis
- [ ] Automated function summaries
- [ ] Machine-readable output
- [ ] JSON output

## ntlinux NT ABI

- [ ] NT types
- [ ] NTSTATUS
- [ ] Object Manager
- [ ] Memory Manager
- [ ] I/O Manager
- [ ] IRP
- [ ] Device objects
- [ ] File objects
- [ ] Synchronization
- [ ] Registry
- [ ] Processes
- [ ] Threads
- [ ] Security
- [ ] PnP
- [ ] Power
- [ ] WMI
- [ ] ETW

## Runtime

- [ ] PE loader
- [ ] Relocation engine
- [ ] Import resolver
- [ ] Driver initialization
- [ ] Driver object model
- [ ] Device object model
- [ ] IRP dispatch
- [ ] NT/Linux ABI bridge
- [ ] Driver isolation

## Testing

- [ ] Minimal toy driver
- [ ] Self-written WDM test driver
- [ ] Simple filesystem driver
- [ ] Additional open-source test drivers
- [ ] Automated regression tests
