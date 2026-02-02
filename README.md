# Cloakwork

**Cloakwork** is an advanced header-only C++20 obfuscation library providing comprehensive protections against static and dynamic analysis. It is highly configurable, extremely modular, and can be embedded directly with no separate compilation step needed. No dependencies required. This was a college project that spiraled into what it is now, so enjoy.

> Inspired by [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h) and Zapcrash's nimrodhide.h

**Author:** ck0i on Discord
**License:** MIT

***

## Features

- **Compile-time string encryption**
  - XTEA block cipher encryption at compile-time, decrypted on-the-fly at runtime.
  - Multi-layer encryption with polymorphic re-encryption (re-keys every N accesses).
  - Stack-based encrypted strings with automatic secure wipe on scope exit.
  - Wide string (wchar_t) encryption support.
  - Stack string builder (`CW_STACK_STR`) for char-by-char construction with no string literal in the binary.
- **Compile-time string hashing**
  - FNV-1a hash computed at compile-time for API name hiding.
  - Runtime hash functions for dynamic string comparison.
  - Case-insensitive hashing variants.
  - Runtime hash macros (`CW_HASH_RT`, `CW_HASH_RT_CI`).
- **Integer/value obfuscation**
  - Protects sensitive values with random key-based encoding and mutation.
  - Mixed Boolean Arithmetic (MBA) obfuscation for arithmetic operations.
  - Full MBA operator set: add, sub, and, or, xor, negation.
  - Obfuscated comparison operators (==, !=, <, >, <=, >=).
  - Encrypted compile-time constants and runtime-keyed constants.
- **Data hiding & scattering**
  - Splits and scrambles user data across memory or in polymorphic wrappers.
  - True heap-based data scattering for structure obfuscation.
- **Control flow obfuscation**
  - Opaque predicates using 8 different runtime entropy sources (stack hash, RDTSC, TID, return address, module base, etc.).
  - Control flow flattening via state machines with XOR-encoded state transitions.
  - Block-level CFG flattening (`CW_FLAT_*`) with encrypted dispatch, dead blocks, and opaque predicates.
  - Simplified CFG protection (`CW_PROTECT`/`CW_PROTECT_VOID`) wrapping arbitrary code in an encrypted state machine.
  - Branch indirection and dead code insertion.
  - Junk code insertion macros.
- **Function pointer obfuscation**
  - XTEA-encrypted function pointer storage with decoy pointer arrays.
  - Return address spoofing via `_AddressOfReturnAddress` intrinsic.
  - Cached ret gadget lookup in ntdll.
- **Import hiding**
  - Dynamic API resolution without import table entries.
  - Module enumeration via PEB walking (user mode) or PsLoadedModuleList (kernel mode).
  - Export table parsing with hash-based lookup and forwarded export resolution.
  - Wide string module resolution (`CW_IMPORT_WIDE`).
  - Convenience macros (`CW_GET_MODULE`, `CW_GET_PROC`) for quick resolution.
- **Direct syscalls**
  - Syscall number extraction from ntdll with Halo's Gate fallback for hooked stubs.
  - Indirect syscall invocation (`CW_SYSCALL`) via shellcode thunk targeting ntdll gadgets.
  - Cached syscall gadget lookup (`syscall; ret` in ntdll .text section).
- **Anti-debugging**
  - Multiple techniques including timing checks, PEB inspection, hardware breakpoint detection.
  - Parent process analysis and debugger window detection.
  - Anti-anti-debug plugin detection (ScyllaHide, TitanHide, HyperHide, etc.).
  - Kernel debugger detection and memory breakpoint detection.
  - Debug port checking via `NtQueryInformationProcess` (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags).
  - Thread hiding from debugger via `NtSetInformationThread` (ThreadHideFromDebugger).
  - Debugger registry artifact detection.
  - Convenience macros for individual checks (`CW_IS_DEBUGGED`, `CW_HAS_HWBP`, `CW_TIMING_CHECK`, etc.).
- **Anti-VM/Sandbox detection**
  - Hypervisor detection via CPUID.
  - VM vendor string detection (VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels, QEMU).
  - Low resource detection (sandbox environments).
  - Sandbox DLL and analysis tool window detection.
  - VM-specific registry key and MAC address detection.
  - Sandbox username/computer name detection (common analysis environment names).
- **Code integrity verification**
  - Function hash computation for tamper detection.
  - Hook detection at function entry points (jmp, push/ret, int3 patterns).
  - Integrity-checked function wrappers.
- **PE header erasure**
  - Zeroes DOS header, NT headers, and section table to prevent memory dumping.
  - Kernel mode variant for driver PE header erasure.
- **IAT scrubbing**
  - Replaces debug-related IAT entries (`IsDebuggerPresent`, `OutputDebugString`, etc.) with stubs.
  - Removes signatures leaked through CRT linkage.
- **Metamorphic code generation**
  - Polymorphic x64 thunk generation with randomized NOP-equivalent instruction padding.
  - Thunks regenerate every N calls producing different machine code each time.
- **Compile-time randomization**
  - All transformations use compile-time random generation -- no two builds are alike.
  - Runtime entropy combining multiple sources (RDTSC, ASLR, hardware RNG via RDSEED).
- **Full modular configuration**
  - Every feature is a toggle -- disable heavy modules for performance or size.

***

## Quick Usage

Add to your project (no build step needed):

```cpp
#include "cloakwork.h"
```

**String Encryption:**
```cpp
const char* msg = CW_STR("secret message");
// automatically decrypted at runtime only

// multi-layer encryption with polymorphic re-encryption
const char* secure = CW_STR_LAYERED("ultra secret");

// stack-based with auto-cleanup on scope exit
auto stack_str = CW_STR_STACK("temporary secret");

// wide string encryption
const wchar_t* wide = CW_WSTR(L"wide string secret");

// stack string builder - never exists as a literal in the binary
CW_STACK_STR(password, 'p','a','s','s','\0');
```

**String Hashing:**
```cpp
// compile-time hash (computed at build time)
constexpr uint32_t hash = CW_HASH("kernel32.dll");

// case-insensitive hash for module names
constexpr uint32_t mod_hash = CW_HASH_CI("ntdll.dll");

// runtime hash of dynamic string
uint32_t h = CW_HASH_RT(some_string);
uint32_t h_ci = CW_HASH_RT_CI(some_string);

// use for API hiding
void* k32 = cloakwork::imports::getModuleBase(CW_HASH_CI("kernel32.dll"));
```

**Obfuscated Values:**
```cpp
// basic obfuscation
int key = CW_INT(0xDEADBEEF);

// MBA (mixed boolean arithmetic) obfuscation
auto mba_val = CW_MBA(42);

// encrypted compile-time constants
int magic = CW_CONST(0xCAFEBABE);

// obfuscated arithmetic operations
int sum = CW_ADD(x, y);
int diff = CW_SUB(x, y);
int xored = CW_XOR(a, b);
int negated = CW_NEG(x);
int masked = CW_AND(x, 0xFF);
int combined = CW_OR(a, b);
```

**Obfuscated Comparisons:**
```cpp
// hide what you're comparing
if (CW_EQ(password_hash, expected_hash)) {
    // authenticated
}

if (CW_LT(health, 0)) {
    // game over
}

// all comparison operators: CW_EQ, CW_NE, CW_LT, CW_GT, CW_LE, CW_GE
```

**Boolean Obfuscation:**
```cpp
// obfuscated true/false using opaque predicates
if (CW_TRUE) {
    // always executes, but looks complex in disassembly
}

// obfuscate any boolean expression
bool result = CW_BOOL(x > 0 && y < 100);
```

**Import Hiding:**
```cpp
// resolve APIs without import table
void* ntdll = cloakwork::imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
void* func = cloakwork::imports::getProcAddress(ntdll, CW_HASH("NtClose"));

// or use the macro
auto pVirtualAlloc = CW_IMPORT("kernel32.dll", VirtualAlloc);

// convenience macros
void* k32 = CW_GET_MODULE("kernel32.dll");
void* fn = CW_GET_PROC(k32, "VirtualAlloc");
```

**Direct Syscalls:**
```cpp
// get syscall number for direct invocation
// uses Halo's Gate fallback if the stub is hooked
uint32_t syscall_num = CW_SYSCALL_NUMBER(NtClose);

// indirect syscall invocation (x64 only)
// sets up registers and jumps to syscall;ret gadget in ntdll
// return address on stack points to ntdll, not your module
NTSTATUS status = CW_SYSCALL(NtClose, handle);
```

**Control Flow Obfuscation:**
```cpp
// obfuscated if/else with opaque predicates
CW_IF(is_authenticated)
    process_secure_data();
CW_ELSE
    handle_error();

// flatten control flow via state machine
auto safe_val = CW_FLATTEN([](int v) { return v * 2; }, user_val);

// insert junk code
CW_JUNK();
CW_JUNK_FLOW();
```

**CFG Flattening (block-level state machine):**
```cpp
// manual block decomposition for maximum protection
int result = CW_FLAT_FUNC(int)
    CW_FLAT_VARS(int x = 0;)
    CW_FLAT_ENTRY(0)
CW_FLAT_BEGIN
    CW_FLAT_BLOCK(0)
        x = input * 2;
        CW_FLAT_GOTO(1)
    CW_FLAT_BLOCK(1)
        CW_FLAT_IF(x > 50, 2, 3)
    CW_FLAT_BLOCK(2)
        CW_FLAT_RETURN(x)
    CW_FLAT_BLOCK(3)
        x += 10;
        CW_FLAT_GOTO(1)
CW_FLAT_END;

// simplified: wrap arbitrary code in an encrypted state machine
int result = CW_PROTECT(int, {
    if (x > 10) return x * 2;
    return x + 5;
});

CW_PROTECT_VOID({
    do_sensitive_work();
});
```

**Anti-Debug:**
```cpp
// comprehensive check (crashes if debugger detected)
CW_ANTI_DEBUG();

// analysis check with advanced techniques
CW_CHECK_ANALYSIS();

// inline check (scatter these throughout your code)
CW_INLINE_CHECK();

// individual checks via convenience macros
if (CW_IS_DEBUGGED()) { /* PEB + NtGlobalFlag */ }
if (CW_HAS_HWBP()) { /* DR0-DR3 */ }
if (CW_CHECK_DEBUG_PORT()) { /* NtQueryInformationProcess */ }
if (CW_DETECT_HIDING()) { /* ScyllaHide, TitanHide, etc. */ }
if (CW_DETECT_PARENT()) { /* parent is a debugger */ }
if (CW_DETECT_KERNEL_DBG()) { /* kernel debugger */ }
if (CW_TIMING_CHECK()) { /* RDTSC vs QPC */ }
if (CW_DETECT_DBG_ARTIFACTS()) { /* debugger registry keys */ }

// hide thread from debugger (ThreadHideFromDebugger)
CW_HIDE_THREAD();
```

**Anti-VM/Sandbox:**
```cpp
// comprehensive check (crashes if VM/sandbox detected)
CW_ANTI_VM();

// or just check
if (CW_CHECK_VM()) {
    // running in VM/sandbox
}

// individual checks
if (CW_DETECT_HYPERVISOR()) { /* CPUID hypervisor bit */ }
if (CW_DETECT_VM_VENDOR()) { /* VMware, VBox, Hyper-V, etc. */ }
if (CW_DETECT_LOW_RESOURCES()) { /* low CPU/RAM */ }
if (CW_DETECT_SANDBOX_DLLS()) { /* sandbox DLLs */ }
```

**Integrity Verification:**
```cpp
// check if function is hooked
if (CW_DETECT_HOOK(VirtualAlloc)) {
    // function has been hooked!
}

// verify multiple functions
bool clean = CW_VERIFY_FUNCS(&func1, &func2);

// compute hash of memory region
uint32_t hash = CW_COMPUTE_HASH(ptr, size);
```

**PE Header Erasure & IAT Scrubbing:**
```cpp
// zero PE headers to prevent memory dumping
CW_ERASE_PE_HEADER();

// replace debug-related IAT entries with stubs
// (IsDebuggerPresent, OutputDebugString, etc.)
CW_SCRUB_DEBUG_IMPORTS();
```

***

## Configuration

Tweak features by defining feature macros **before** including the header:

```cpp
#define CW_ENABLE_METAMORPHIC 0
#define CW_ENABLE_STRING_ENCRYPTION 1
#include "cloakwork.h"
```

### Configuration Options

- `CW_ENABLE_ALL` -- Master on/off switch (default: 1)
- `CW_ENABLE_STRING_ENCRYPTION` -- String encryption (default: 1)
- `CW_ENABLE_VALUE_OBFUSCATION` -- Integer/value obfuscation (default: 1)
- `CW_ENABLE_CONTROL_FLOW` -- Control flow obfuscation (default: 1)
- `CW_ENABLE_ANTI_DEBUG` -- Anti-debugging features (default: 1)
- `CW_ENABLE_FUNCTION_OBFUSCATION` -- Function pointer obfuscation (default: 1)
- `CW_ENABLE_DATA_HIDING` -- Data scattering/polymorphic values (default: 1)
- `CW_ENABLE_METAMORPHIC` -- Metamorphic code generation (default: 1)
- `CW_ENABLE_COMPILE_TIME_RANDOM` -- Compile-time randomization (default: 1)
- `CW_ENABLE_IMPORT_HIDING` -- Dynamic API resolution (default: 1)
- `CW_ENABLE_SYSCALLS` -- Direct syscall support (default: 1)
- `CW_ENABLE_ANTI_VM` -- Anti-VM/sandbox detection (default: 1)
- `CW_ENABLE_INTEGRITY_CHECKS` -- Code integrity verification (default: 1)
- `CW_ANTI_DEBUG_RESPONSE` -- Response to debugger detection: 0=ignore, 1=crash, 2=fake data (default: 1)

All features are **enabled by default**. For minimal configuration:

```cpp
#define CW_ENABLE_ALL 0                      // disable everything first
#define CW_ENABLE_STRING_ENCRYPTION 1        // enable only what you need
#define CW_ENABLE_VALUE_OBFUSCATION 1
#include "cloakwork.h"
```

Performance-focused configuration:

```cpp
#define CW_ENABLE_METAMORPHIC 0              // disable heavy features
#define CW_ENABLE_CONTROL_FLOW 0
#include "cloakwork.h"
```

***

## Kernel Mode Support

Cloakwork supports Windows kernel mode drivers (WDM/KMDF). Kernel mode is automatically detected when WDK headers are present (`_KERNEL_MODE`, `NTDDI_VERSION`, `_NTDDK_`, `_WDMDDK_`), or can be forced with `CW_KERNEL_MODE 1`.

**Important:** Due to the constraints of kernel mode (no STL, no CRT atexit, no C++20 concepts), most obfuscation features are **disabled by default** in kernel mode. See the feature table below for details.

### Kernel Mode Usage

```cpp
#include <ntddk.h>
#define CW_KERNEL_MODE 1  // optional - auto-detected from ntddk.h
#include "cloakwork.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // compile-time string hashing works (no encryption - see limitations)
    constexpr uint32_t nt_hash = CW_HASH("NtClose");
    DbgPrint("NtClose hash: 0x%X\n", nt_hash);

    // compile-time random works
    constexpr uint32_t random_key = CW_RANDOM_CT();
    DbgPrint("Compile-time random: 0x%X\n", random_key);

    // runtime random with kernel entropy sources
    uint64_t runtime_key = CW_RANDOM_RT();
    DbgPrint("Runtime random: 0x%llX\n", runtime_key);

    // anti-debug detects kernel debuggers
    if (cloakwork::anti_debug::is_debugger_present()) {
        DbgPrint("Kernel debugger detected!\n");
        // KdDebuggerEnabled, KdDebuggerNotPresent, or PsIsProcessBeingDebugged
    }

    // hardware breakpoint detection via debug registers
    if (cloakwork::anti_debug::has_hardware_breakpoints()) {
        DbgPrint("Hardware breakpoints detected (DR0-DR3)\n");
    }

    // NOTE: CW_STR, CW_INT, CW_IF, etc. are NO-OPS in kernel mode
    // they compile to plain values without obfuscation
    const char* msg = CW_STR("this is NOT encrypted in kernel mode");

    DriverObject->DriverUnload = [](PDRIVER_OBJECT) {
        DbgPrint("Driver unloading\n");
    };

    return STATUS_SUCCESS;
}
```

### Kernel Mode Internals

In kernel mode, Cloakwork provides STL-compatible replacements and kernel primitives:

| Component | User Mode | Kernel Mode |
|-----------|-----------|-------------|
| Thread Safety | `std::mutex` | `KSPIN_LOCK` via `kernel_spinlock` |
| Atomics | `std::atomic<T>` | `Interlocked*` via `kernel_atomic<T>` |
| Memory Allocation | `new`/`HeapAlloc` | `ExAllocatePool2`/`ExFreePoolWithTag` |
| Random Entropy | `QueryPerformanceCounter`, PIDs, heap addresses | `KeQueryPerformanceCounter`, `KeQueryInterruptTime`, KASLR, pool addresses |
| Debugger Detection | PEB `BeingDebugged`, `IsDebuggerPresent` | `KdDebuggerEnabled`, `KdDebuggerNotPresent`, `PsIsProcessBeingDebugged` |
| Debug Registers | `GetThreadContext` | Direct `__readdr()` intrinsic |
| Exception Safety | SEH (`__try/__except`) | `MmIsAddressValid` checks |
| Type Traits | `<type_traits>` | Custom `std::is_integral`, `std::enable_if`, etc. |
| Index Sequence | `std::index_sequence` | Custom implementation |
| Array | `std::array<T, N>` | Custom implementation |
| Rotate | `std::rotl`/`std::rotr` | Custom implementation |

### Kernel Mode Feature Availability

**Enabled in kernel mode:**
- `CW_ENABLE_COMPILE_TIME_RANDOM` - compile-time and runtime random generation
- `CW_ENABLE_ANTI_DEBUG` - kernel debugger detection
- String hashing (`CW_HASH`, `CW_HASH_CI`, `CW_HASH_WIDE`) - consteval, always works

**Disabled in kernel mode (compile to no-ops):**

| Feature | Reason Disabled | Effect |
|---------|-----------------|--------|
| `CW_ENABLE_STRING_ENCRYPTION` | Uses static destructors requiring `atexit` | `CW_STR(s)` -> `(s)` |
| `CW_ENABLE_VALUE_OBFUSCATION` | Uses C++20 concepts and `std::bit_cast` | `CW_INT(x)` -> no obfuscation |
| `CW_ENABLE_CONTROL_FLOW` | Depends on MBA from value obfuscation | `CW_IF` -> regular `if` |
| `CW_ENABLE_FUNCTION_OBFUSCATION` | Uses C++20 concepts | `CW_CALL(f)` -> no obfuscation |
| `CW_ENABLE_DATA_HIDING` | Uses `std::unique_ptr` | `CW_SCATTER` unavailable |
| `CW_ENABLE_METAMORPHIC` | Uses `std::initializer_list` | Metamorphic functions unavailable |
| `CW_ENABLE_IMPORT_HIDING` | PEB walking needs usermode structures | `CW_IMPORT` unavailable |
| `CW_ENABLE_ANTI_VM` | Uses usermode APIs (`GetSystemInfo`, registry) | `CW_ANTI_VM()` -> no-op |
| `CW_ENABLE_INTEGRITY_CHECKS` | Requires `VirtualQuery` | Hook detection unavailable |
| `CW_ENABLE_SYSCALLS` | Already in kernel, not applicable | `CW_SYSCALL_NUMBER` -> 0 |

### Kernel Anti-Debug Techniques

The kernel mode anti-debug uses these detection methods:

1. **KdDebuggerEnabled** - Global kernel flag set when kernel debugger is attached
2. **KdDebuggerNotPresent** - Inverse flag (false = debugger present)
3. **PsIsProcessBeingDebugged** - Per-process debug port check (dynamically resolved via `MmGetSystemRoutineAddress`)
4. **Debug Registers** - Direct `__readdr()` intrinsic to read DR0-DR3 hardware breakpoints
5. **Timing Analysis** - `KeQueryPerformanceCounter` vs RDTSC comparison for step detection

```cpp
// comprehensive kernel debugger check
if (cloakwork::anti_debug::comprehensive_check()) {
    // kernel debugger or hardware breakpoints detected
    KeBugCheckEx(0xDEAD, 0, 0, 0, 0);
}

// individual checks
if (cloakwork::anti_debug::is_debugger_present()) {
    // KdDebuggerEnabled or PsIsProcessBeingDebugged
}

if (cloakwork::anti_debug::has_hardware_breakpoints()) {
    // DR0-DR3 are non-zero
}

// timing check with callback
bool suspicious = cloakwork::anti_debug::timing_check([]() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
}, 50000);
```

### Kernel Random Entropy Sources

Runtime random in kernel mode combines multiple entropy sources:
- `__rdtsc()` - CPU cycle counter
- `PsGetCurrentProcess()` / `PsGetCurrentThread()` - KASLR randomized addresses
- `PsGetCurrentProcessId()` / `PsGetCurrentThreadId()` - Process/thread IDs
- `KeQueryPerformanceCounter()` - High-precision timer
- `KeQuerySystemTime()` - System time
- `KeQueryInterruptTime()` - Interrupt time (very high resolution)
- Pool allocation address - KASLR randomized heap location
- Stack address - KASLR randomized

All sources are mixed using xorshift64* for fast, quality pseudorandom output.

***

## API Reference

### String Encryption

- `CW_STR(s)` -- Compile-time XTEA-encrypted string, decrypts at runtime
- `CW_STR_LAYERED(s)` -- Multi-layer encrypted string with polymorphic re-encryption
- `CW_STR_STACK(s)` -- Stack-based encrypted string with secure wipe on scope exit
- `CW_WSTR(s)` -- Wide string (wchar_t) encryption
- `CW_STACK_STR(name, ...)` -- Build string char-by-char on stack (no literal in binary)

### String Hashing

- `CW_HASH(s)` -- Compile-time FNV-1a hash of string (case-sensitive, for function names)
- `CW_HASH_CI(s)` -- Compile-time case-insensitive hash (for module names)
- `CW_HASH_WIDE(s)` -- Compile-time hash of wide string
- `CW_HASH_RT(str)` -- Runtime FNV-1a hash (case-sensitive)
- `CW_HASH_RT_CI(str)` -- Runtime FNV-1a hash (case-insensitive)
- `cloakwork::hash::fnv1a_runtime(str)` -- Runtime hash of string
- `cloakwork::hash::fnv1a_runtime_ci(str)` -- Case-insensitive runtime hash

### Value Obfuscation

- `CW_INT(x)` -- Obfuscated integer/numeric value
- `CW_MBA(x)` -- MBA (Mixed Boolean Arithmetic) obfuscated value
- `CW_CONST(x)` -- Encrypted compile-time constant
- `CW_ADD(a, b)` -- Obfuscated addition using MBA
- `CW_SUB(a, b)` -- Obfuscated subtraction using MBA
- `CW_AND(a, b)` -- Obfuscated bitwise AND using MBA
- `CW_OR(a, b)` -- Obfuscated bitwise OR using MBA
- `CW_XOR(a, b)` -- Obfuscated bitwise XOR using MBA
- `CW_NEG(a)` -- Obfuscated negation using MBA (~x + 1)

### Obfuscated Comparisons

- `CW_EQ(a, b)` -- Obfuscated equality (a == b)
- `CW_NE(a, b)` -- Obfuscated not-equals (a != b)
- `CW_LT(a, b)` -- Obfuscated less-than (a < b)
- `CW_GT(a, b)` -- Obfuscated greater-than (a > b)
- `CW_LE(a, b)` -- Obfuscated less-or-equal (a <= b)
- `CW_GE(a, b)` -- Obfuscated greater-or-equal (a >= b)

### Boolean Obfuscation

- `CW_TRUE` -- Obfuscated true using opaque predicates
- `CW_FALSE` -- Obfuscated false using opaque predicates
- `CW_BOOL(expr)` -- Obfuscates any boolean expression

### Data Hiding

- `CW_SCATTER(x)` -- Scatters data across heap allocations
- `CW_POLY(x)` -- Polymorphic value that mutates internally

### Control Flow

- `CW_IF(expr)` -- Obfuscated if with opaque predicates
- `CW_ELSE` -- Obfuscated else clause
- `CW_BRANCH(cond)` -- Indirect branching with obfuscation
- `CW_FLATTEN(func, ...)` -- Flattens control flow via state machine
- `CW_JUNK()` -- Insert junk computation
- `CW_JUNK_FLOW()` -- Insert junk with fake control flow

### CFG Flattening (Block-Level State Machine)

Manual block-level control flow flattening with encrypted state transitions, dead blocks, and opaque predicates. Produces decompiler-hostile output that IDA/Hex-Rays shows as a complex state machine.

- `CW_FLAT_FUNC(ret_type)` -- Begin flattened function returning ret_type
- `CW_FLAT_VOID` -- Begin void flattened function
- `CW_FLAT_VARS(...)` -- Declare shared variables across blocks
- `CW_FLAT_ENTRY(id)` -- Set entry block ID
- `CW_FLAT_BEGIN` -- Begin dispatch loop (auto-inserts dead blocks)
- `CW_FLAT_BLOCK(id)` -- Start a block with given ID
- `CW_FLAT_GOTO(id)` -- Unconditional jump to block
- `CW_FLAT_GOTO_OBF(id)` -- Obfuscated jump (adds fake dead-block branch)
- `CW_FLAT_IF(cond, true_id, false_id)` -- Conditional branch
- `CW_FLAT_IF_OBF(cond, true_id, false_id)` -- Obfuscated conditional (volatile + opaque predicate)
- `CW_FLAT_RETURN(val)` -- Return value and exit
- `CW_FLAT_EXIT()` -- Exit without return value
- `CW_FLAT_SWITCH2..4(expr, ...)` -- Multi-way dispatch (2-4 cases + default)
- `CW_FLAT_END` -- Close dispatch loop (non-void)
- `CW_FLAT_VOID_END` -- Close dispatch loop (void)

### Simplified CFG Protection

Wraps arbitrary code in an encrypted state machine dispatcher without manual block decomposition.

- `CW_PROTECT(ret_type, body)` -- Wraps code in encrypted state machine, returns ret_type
- `CW_PROTECT_VOID(body)` -- Wraps void code in encrypted state machine

### Function Protection

- `CW_CALL(func)` -- Obfuscates function pointer with XTEA encryption and decoy arrays
- `CW_SPOOF_CALL(func)` -- Call with spoofed return address
- `CW_RET_GADGET()` -- Get cached ret gadget for return address spoofing

### Import Hiding

- `CW_IMPORT(mod, func)` -- Resolve function without import table
- `CW_IMPORT_WIDE(mod, func)` -- Resolve function using wide string module hash
- `CW_GET_MODULE(name)` -- Get module base via PEB walk (string -> hash)
- `CW_GET_PROC(mod, func)` -- Get function address via export walk (string -> hash)
- `cloakwork::imports::getModuleBase(hash)` -- Get module base by hash
- `cloakwork::imports::getProcAddress(mod, hash)` -- Get function by hash

### Direct Syscalls

- `CW_SYSCALL_NUMBER(func)` -- Get syscall number for ntdll function (with Halo's Gate fallback)
- `CW_SYSCALL(func, ...)` -- Indirect syscall invocation via ntdll gadget (x64 only)
- `cloakwork::syscall::getSyscallNumber(hash)` -- Get syscall by function hash
- `cloakwork::syscall::invokeSyscall(number, ...)` -- Invoke syscall via shellcode thunk

### Anti-Debugging

- `CW_ANTI_DEBUG()` -- Crashes if debugger detected
- `CW_CHECK_ANALYSIS()` -- Advanced anti-analysis check
- `CW_INLINE_CHECK()` -- Inline anti-debug check
- `CW_IS_DEBUGGED()` -- PEB BeingDebugged + NtGlobalFlag check
- `CW_HAS_HWBP()` -- Hardware breakpoint detection (DR0-DR3)
- `CW_CHECK_DEBUG()` -- Comprehensive multi-layer detection
- `CW_CHECK_DEBUG_PORT()` -- Debug port check via NtQueryInformationProcess
- `CW_HIDE_THREAD()` -- Hide thread from debugger (ThreadHideFromDebugger)
- `CW_DETECT_HIDING()` -- Detect anti-anti-debug tools (ScyllaHide, etc.)
- `CW_DETECT_PARENT()` -- Check if parent is a debugger
- `CW_DETECT_KERNEL_DBG()` -- Kernel debugger detection
- `CW_TIMING_CHECK()` -- RDTSC vs QPC timing check
- `CW_DETECT_DBG_ARTIFACTS()` -- Debugger registry artifact detection
- `cloakwork::anti_debug::is_debugger_present()` -- Basic debugger detection
- `cloakwork::anti_debug::comprehensive_check()` -- Multi-layer detection

### Anti-VM/Sandbox

- `CW_ANTI_VM()` -- Crashes if VM/sandbox detected
- `CW_CHECK_VM()` -- Returns true if VM/sandbox detected
- `CW_DETECT_HYPERVISOR()` -- CPUID hypervisor bit check
- `CW_DETECT_VM_VENDOR()` -- VM vendor string detection
- `CW_DETECT_LOW_RESOURCES()` -- Low CPU/RAM/disk detection
- `CW_DETECT_SANDBOX_DLLS()` -- Sandbox DLL and analysis tool detection
- `cloakwork::anti_debug::anti_vm::comprehensive_check()` -- Full VM/sandbox detection
- `cloakwork::anti_debug::anti_vm::detect_sandbox_names()` -- Sandbox username/computer name detection
- `cloakwork::anti_debug::anti_vm::detect_vm_registry()` -- VM registry key detection
- `cloakwork::anti_debug::anti_vm::detect_vm_mac()` -- VM MAC address prefix detection

### Integrity Verification

- `CW_DETECT_HOOK(func)` -- Check if function is hooked
- `CW_INTEGRITY_CHECK(func, size)` -- Wrap function with integrity checking
- `CW_COMPUTE_HASH(ptr, size)` -- Compute hash of memory region
- `CW_VERIFY_FUNCS(...)` -- Verify multiple functions aren't hooked
- `cloakwork::integrity::computeHash(data, size)` -- Compute hash of memory
- `cloakwork::integrity::detectHook(func)` -- Check for hook patterns
- `cloakwork::integrity::verifyFunctions(...)` -- Verify multiple functions

### PE Header Erasure

- `CW_ERASE_PE_HEADER()` -- Zero DOS/NT headers and section table to prevent dumping
- `cloakwork::pe_erase::erase_pe_header()` -- User mode PE header erasure
- `cloakwork::pe_erase::erase_driver_header(base)` -- Kernel mode driver header erasure

### IAT Scrubbing

- `CW_SCRUB_DEBUG_IMPORTS()` -- Replace debug-related IAT entries with stubs

### Random Number Generation

- `CW_RANDOM_CT()` -- Compile-time random value (unique per build)
- `CW_RAND_CT(min, max)` -- Compile-time random in range
- `CW_RANDOM_RT()` -- Runtime random value (unique per execution)
- `CW_RAND_RT(min, max)` -- Runtime random in range

### Template Classes & Type Aliases

- `cloakwork::obfuscated_value<T>` -- Generic value obfuscation
- `cloakwork::mba_obfuscated<T>` -- MBA-based obfuscation
- `cloakwork::bool_obfuscation::obfuscated_bool` -- Multi-byte boolean storage
- `cloakwork::data_hiding::scattered_value<T, Chunks>` -- Data scattering
- `cloakwork::data_hiding::polymorphic_value<T>` -- Polymorphic value
- `cloakwork::obfuscated_call<Func>` -- Function pointer obfuscation
- `cloakwork::metamorphic::metamorphic_function<Func>` -- Metamorphic wrapper with thunk regeneration
- `cloakwork::constants::runtime_constant<T>` -- Runtime-keyed constant
- `cloakwork::integrity::integrity_checked<Func>` -- Integrity-checked function
- `cloakwork::obf_bool` -- Shorthand for `obfuscated_bool`
- `cloakwork::meta_func<Sig>` -- Shorthand for `metamorphic_function<Sig>`
- `cloakwork::rt_const<T>` -- Shorthand for `runtime_constant<T>`

***

## Advanced Integration

All features are **header-only** and are **Windows-focused** (with advanced anti-debug using Win32 APIs). C++20 or above required.

- Deep integration possible with scatter/polymorphic wrappers for sensitive data structures.
- Metamorphic functions generate randomized x64 thunks with NOP-equivalent instruction padding, regenerating every 1000 calls.
- Import hiding removes sensitive APIs from import table, resolving at runtime via PEB walking with forwarded export resolution.
- Direct syscalls bypass usermode hooks entirely via indirect invocation through ntdll gadgets, with Halo's Gate fallback for hooked stubs.
- PE header erasure and IAT scrubbing eliminate dump artifacts and debug-related import signatures.
- Anti-debug techniques include:
  - PEB inspection (BeingDebugged flag, NtGlobalFlag)
  - Hardware breakpoint detection via debug registers
  - Timing analysis (RDTSC vs QueryPerformanceCounter)
  - Parent process analysis
  - Debugger window class detection
  - Anti-anti-debug plugin detection (ScyllaHide, TitanHide, HyperHide)
  - Kernel debugger detection
  - Memory breakpoint (PAGE_GUARD) detection
  - Debug port checking (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags)
  - Thread hiding from debugger (ThreadHideFromDebugger)
  - Debugger registry artifact detection
- Anti-VM techniques include:
  - Hypervisor bit detection via CPUID
  - VM vendor string matching (VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels, QEMU)
  - Low resource detection (CPU count, RAM, disk size)
  - VM-specific registry keys
  - VM MAC address prefix detection
  - Sandbox DLL and analysis tool window detection
  - Sandbox username/computer name detection
- Control flow flattening uses XOR-encrypted state machines with dead blocks and 8 types of opaque predicates to frustrate static analysis.
- Block-level CFG flattening (`CW_FLAT_*`) provides manual control over state machine decomposition, while `CW_PROTECT` offers automatic wrapping.
- String encryption uses XTEA block cipher (32 rounds, 128-bit key) with optional polymorphic re-encryption.
- All anti-debug/anti-VM string comparisons use hash-based matching with compile-time encrypted registry paths -- no plaintext signatures in the binary.

***

## Credits

- Inspired by legendary tools: obfusheader.h, nimrodhide.h, and the anti-re tools of unknowncheats.
- Created by helz.dev/Helzky / Discord: `ck0i`
- Open for contributions and issues!

***

## License

MIT License -- do what you want, no warranty.

***

**Cloakwork: Ultra-obfuscated, ultra-useful... Happy hiding!**

---

