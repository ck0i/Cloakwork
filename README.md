# Cloakwork

Cloakwork is a single-header C++20 obfuscation library for Windows. Include `cloakwork.h` to use encoded strings and values, mixed Boolean arithmetic, control-flow wrappers, and an explicit integer bytecode VM. Existing Windows integration APIs remain available. MSVC auto-links the Windows libraries used by the header.

The current regression target is MSVC x64. Kernel interfaces remain in the header but are not covered by the user-mode test suite.

Obfuscation changes how code and data appear in a binary. It does not keep secrets from someone who can inspect the running process. The custom transforms and embedded keys are recoverable; additional rounds, product terms, or bytecode do not establish cryptographic security or measured resistance to a decompiler.

> Inspired by [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h), Zapcrash's nimrodhide.h, and qengine.

**Author:** ck0i on Discord | **License:** MIT

---

## Quick Start

```cpp
#include "cloakwork.h"
```

```cpp
// encrypted at compile-time, decrypted at runtime
const char* secret = CW_STR("my secret string");
```

```cpp
// compile-time FNV-1a hash for API name hiding
constexpr uint32_t hash = CW_HASH("kernel32.dll");
constexpr uint32_t hash_ci = CW_HASH_CI("ntdll.dll");
```

```cpp
// obfuscated integer with random key encoding
int key = CW_INT(0xDEAD);
```

```cpp
// resolve API without import table entry
auto pVirtualAlloc = CW_IMPORT("kernel32.dll", VirtualAlloc);
```

```cpp
// crash if debugger detected, or check as bool
CW_ANTI_DEBUG();
if (CW_CHECK_DEBUG()) { /* debugger present */ }
```

```cpp
// crash if VM/sandbox detected, or check as bool
CW_ANTI_VM();
if (CW_CHECK_VM()) { /* virtualized */ }
```

```cpp
// wrap code in an encrypted state machine
int result = CW_PROTECT(int, {
    if (x > 10) return x * 2;
    return x + 5;
});
```

```cpp
// indirect syscall via ntdll gadget (x64)
NTSTATUS status = CW_SYSCALL(NtClose, handle);
```

---

## Configuration

Define feature macros **before** including the header. All features are enabled by default.

| Macro | Description | Default |
|-------|-------------|---------|
| `CW_ENABLE_ALL` | Master on/off switch | `1` |
| `CW_ENABLE_STRING_ENCRYPTION` | Compile-time string encoding | `1` |
| `CW_ENABLE_VALUE_OBFUSCATION` | Integer/value obfuscation and MBA | `1` |
| `CW_ENABLE_CONTROL_FLOW` | Control flow obfuscation | `1` |
| `CW_ENABLE_ANTI_DEBUG` | Anti-debugging features | `1` |
| `CW_ENABLE_FUNCTION_OBFUSCATION` | Function pointer obfuscation | `1` |
| `CW_ENABLE_DATA_HIDING` | Scattered/polymorphic values | `1` |
| `CW_ENABLE_METAMORPHIC` | Metamorphic code generation | `1` |
| `CW_ENABLE_COMPILE_TIME_RANDOM` | Compile-time random generation | `1` |
| `CW_ENABLE_IMPORT_HIDING` | Dynamic API resolution | `1` |
| `CW_ENABLE_SYSCALLS` | Direct syscall invocation | `1` |
| `CW_ENABLE_ANTI_VM` | Anti-VM/sandbox detection | `1` |
| `CW_ENABLE_INTEGRITY_CHECKS` | Code integrity verification | `1` |
| `CW_BUILD_SEED` | Shared build seed for reproducible encodings | `0xC10A2026u` |
| `CW_ANTI_DEBUG_RESPONSE` | Debugger response: 0=ignore, 1=crash, 2=fake data | `1` |

If you disable `CW_ENABLE_ALL` and selectively re-enable features, Cloakwork
now emits compile-time errors for unsupported combinations. String encryption,
value obfuscation, anti-debug, data hiding, control flow, metamorphic code,
function obfuscation, and import hiding depend on `CW_ENABLE_COMPILE_TIME_RANDOM`.
Function obfuscation and syscalls also depend on import hiding because they scan
loaded PE images for gadgets and exports.

---

## API Reference

### String Encryption

| Macro | Description |
|-------|-------------|
| `CW_STR(s)` | Compile-time encoded string with a stable runtime plaintext cache |
| `CW_STR_LAYERED(s)` | Two encoding passes with separate keys and a stable plaintext cache |
| `CW_STR_STACK(s)` | Decrypt into an owning local buffer; wipe that buffer on destruction |
| `CW_WSTR(s)` | Wide string (wchar_t) encryption |
| `CW_STACK_STR(name, ...)` | Char-by-char initializer; the compiler may emit a literal |

### String Hashing

| Macro | Description |
|-------|-------------|
| `CW_HASH(s)` | Compile-time FNV-1a hash (case-sensitive) |
| `CW_HASH_CI(s)` | Compile-time FNV-1a hash (case-insensitive) |
| `CW_HASH_WIDE(s)` | Compile-time wide string hash |
| `CW_HASH_WIDE_CI(s)` | Compile-time wide module-name hash for `CW_IMPORT_WIDE` |
| `CW_HASH_RT(str)` | Runtime FNV-1a hash (case-sensitive) |
| `CW_HASH_RT_CI(str)` | Runtime FNV-1a hash (case-insensitive) |

### Value Obfuscation

| Macro | Description |
|-------|-------------|
| `CW_INT(x)` | Obfuscated integer with random key encoding |
| `CW_MBA(x)` | Mixed Boolean Arithmetic obfuscation |
| `CW_CONST(x)` | Encrypted compile-time constant |
| `CW_ADD(a, b)` | Obfuscated addition via MBA |
| `CW_SUB(a, b)` | Obfuscated subtraction via MBA |
| `CW_AND(a, b)` | Obfuscated bitwise AND via MBA |
| `CW_OR(a, b)` | Obfuscated bitwise OR via MBA |
| `CW_XOR(a, b)` | Obfuscated bitwise XOR via MBA |
| `CW_NEG(a)` | Obfuscated negation via MBA |

### Comparisons

| Macro | Description |
|-------|-------------|
| `CW_EQ(a, b)` | Obfuscated equality (==) |
| `CW_NE(a, b)` | Obfuscated not-equals (!=) |
| `CW_LT(a, b)` | Obfuscated less-than (<) |
| `CW_GT(a, b)` | Obfuscated greater-than (>) |
| `CW_LE(a, b)` | Obfuscated less-or-equal (<=) |
| `CW_GE(a, b)` | Obfuscated greater-or-equal (>=) |

### Booleans

| Macro | Description |
|-------|-------------|
| `CW_TRUE` | Opaque predicate that evaluates to true |
| `CW_FALSE` | Opaque predicate that evaluates to false |
| `CW_BOOL(expr)` | Obfuscate any boolean expression |

### Control Flow

| Macro | Description |
|-------|-------------|
| `CW_IF(cond)` | Obfuscated branching with opaque predicates |
| `CW_ELSE` | Obfuscated else clause |
| `CW_BRANCH(cond)` | Indirect branching with obfuscation |
| `CW_FLATTEN(func, ...)` | Invoke a callable through a dispatcher |
| `CW_PROTECT(ret_type, body)` | Invoke a native C++ body through a dispatcher |
| `CW_PROTECT_VOID(body)` | Void variant of `CW_PROTECT` |
| `CW_JUNK()` | Insert junk computation |
| `CW_JUNK_FLOW()` | Insert junk with fake control flow |

### Function Protection

| Macro | Description |
|-------|-------------|
| `CW_CALL(func)` | Runtime-encoded function pointer with decoy arrays |
| `CW_SPOOF_CALL(func)` | Call with spoofed return address |
| `CW_RET_GADGET()` | Cached ret gadget in ntdll for return address spoofing |

### Import Hiding

| Macro | Description |
|-------|-------------|
| `CW_IMPORT(mod, func)` | Dynamic resolution without import table entry |
| `CW_IMPORT_WIDE(mod, func)` | Wide string module variant |
| `CW_GET_MODULE(name)` | Get module base via PEB walk |
| `CW_GET_PROC(mod, func)` | Get export address by hash |

### Direct Syscalls

| Macro | Description |
|-------|-------------|
| `CW_SYSCALL_NUMBER(func)` | Extract syscall number with Halo's Gate fallback |
| `CW_SYSCALL(func, ...)` | Indirect invocation via ntdll gadget (x64 only) |

### Data Hiding

| Macro | Description |
|-------|-------------|
| `CW_SCATTER(x)` | Heap-scattered data across multiple allocations |
| `CW_POLY(x)` | Encoded arithmetic storage, rekeyed every 100 reads or explicitly with `.rekey()` |

### Anti-Debug

| Macro | Description |
|-------|-------------|
| `CW_ANTI_DEBUG()` | Crashes if debugger detected (multi-technique) |
| `CW_CHECK_DEBUG()` | Returns bool, comprehensive multi-layer detection |
| `CW_HIDE_THREAD()` | Hide thread from debugger (ThreadHideFromDebugger) |

For granular checks, use the `cloakwork::anti_debug` namespace directly: `is_debugger_present()`, `has_hardware_breakpoints()`, `comprehensive_check()`, and `timing_check()`. The `advanced` sub-namespace contains hiding-tool, parent-process, kernel-debugger, timing, memory-breakpoint, and registry-artifact checks. The `enhanced` sub-namespace contains debug-port probing and thread hiding.

### Anti-VM / Sandbox

| Macro | Description |
|-------|-------------|
| `CW_ANTI_VM()` | Crashes if VM or sandbox detected |
| `CW_CHECK_VM()` | Returns bool |

For individual checks, use `cloakwork::anti_debug::anti_vm`: hypervisor detection (CPUID), VM vendor string matching (VMware, VirtualBox, KVM, Xen, Parallels, QEMU), low resource detection, sandbox DLL detection, VM registry keys, VM MAC prefixes, and sandbox username/computer name detection. Hyper-V/VBS is treated as corroborating evidence rather than a standalone VM verdict to reduce false positives on modern bare-metal Windows.

### Integrity

| Macro | Description |
|-------|-------------|
| `CW_DETECT_HOOK(func)` | Check for hook patterns (jmp, push/ret, int3) at entry point |
| `CW_INTEGRITY_CHECK(func, size)` | Integrity-checked function wrapper |
| `CW_COMPUTE_HASH(ptr, size)` | Hash a memory region |
| `CW_VERIFY_FUNCS(...)` | Verify multiple functions are not hooked |

### PE / IAT

| Macro | Description |
|-------|-------------|
| `CW_ERASE_PE_HEADER()` | Zero DOS/NT headers and section table to prevent dumping |
| `CW_SCRUB_DEBUG_IMPORTS()` | Stub debug-related IAT entries (IsDebuggerPresent, etc.) |

### Random

| Macro | Description |
|-------|-------------|
| `CW_RANDOM_CT()` | Compile-time value derived from the build seed and expansion location |
| `CW_RAND_CT(min, max)` | Compile-time random in range |
| `CW_RANDOM_RT()` | Runtime random value (multi-source entropy) |
| `CW_RAND_RT(min, max)` | Runtime random in range |

### Template Classes

- `cloakwork::obfuscated_value<T>` -- generic value obfuscation
- `cloakwork::mba_obfuscated<T>` -- MBA-based obfuscation
- `cloakwork::obfuscated_call<Func>` -- function pointer obfuscation
- `cloakwork::meta_func<Sig>` -- metamorphic function wrapper (alias for `metamorphic_function<Sig>`)
- `cloakwork::data_hiding::scattered_value<T, Chunks>` -- heap data scattering
- `cloakwork::data_hiding::polymorphic_value<T>` -- polymorphic mutating value
- `cloakwork::constants::runtime_constant<T>` -- runtime-keyed constant (alias: `cloakwork::rt_const<T>`)
- `cloakwork::integrity::integrity_checked<Func>` -- integrity-checked function wrapper
- `cloakwork::obf_bool` -- obfuscated boolean (multi-byte storage with opaque predicates)

---

## Compatibility and storage contracts

The public macro names remain available. Recompile all translation units after replacing the header; the class layouts have changed. Use the same feature definitions and `CW_BUILD_SEED` in every translation unit. The default seed is deterministic. For different encodings per release, set a new shared seed in the build configuration, for example `/DCW_BUILD_SEED=0x12AB34CDu`. The seed is not secret. Internal defaults no longer depend on include-time `__COUNTER__` state or compilation time.

`CW_INT`, `CW_MBA`, and `CW_POLY` retain `.get()`, `.set()`, and implicit value conversion. Their reads and writes now use a mutex, and they support copying. This adds synchronization overhead. `CW_INT` and `CW_POLY` preserve floating-point representations, including negative zero and NaN payloads. Their encoded storage uses byte Feistel transforms; `CW_POLY` replaces its keys and encoded bytes without changing the decoded value. These value wrappers no longer perform implicit periodic debugger checks. Use the explicit anti-debug API when that behavior is required.

`CW_ADD`, `CW_SUB`, `CW_AND`, `CW_OR`, `CW_XOR`, and `CW_NEG` evaluate each operand once. Integer promotions apply to macro results. Addition, subtraction, and negation wrap at the result width, including signed results; they do not use signed overflow internally. Direct typed `mba` helpers retain the requested width. Addition includes product-based variants with volatile intermediates. These expressions remain algebraically simplifiable. Comparisons preserve native mixed-type conversions and NaN ordering. `CW_RAND_CT` and `CW_RAND_RT` evaluate each bound once, support the full integer range, and reject reversed bounds. They use modulo mapping and are not guaranteed to be uniformly distributed.

`CW_STR`, `CW_STR_LAYERED`, and `CW_WSTR` return a pointer that remains valid until the macro's static object is destroyed. After first use, that object's plaintext cache remains readable and is never rekeyed in place. The cache is wiped on destruction. The layered variant now performs two encoding passes instead of briefly rewriting plaintext while other callers might be reading it.

Keep stack strings in a named variable:

```cpp
auto secret = CW_STR_STACK("local plaintext");
consume(secret.get());
```

The immutable static payload is decoded directly into `secret`, without populating a static plaintext cache. Its owned buffer is wiped on destruction. Copies own separate buffers. Getting a pointer from an unnamed temporary is now a compile error, preventing the common dangling-pointer form `const char* p = CW_STR_STACK("text");`. Wiping owned buffers cannot erase copies made by application code, registers, or the operating system.

`CW_SCATTER` accepts trivially copyable types. It commits a replacement only after all allocations succeed. It does not prevent a process memory dump. Destroying any wrapper while another thread uses it remains invalid.

`CW_FLATTEN` and `CW_PROTECT` preserve void, reference, and move-only returns, and propagate exceptions. A protected body remains native C++ inside a callable. Its internal branches are not converted into bytecode or flattened automatically. `CW_CALL` also accepts function-pointer variables and preserves reference returns. Metamorphic function calls retain ownership of an executable page until the call completes, so regeneration cannot free a page that another caller still uses. The initializer-list constructor continues to use the first function; empty lists are rejected when metamorphic protection is enabled.

As before, disabling features can make their macros return raw values instead of wrappers. Do not depend on `.get()` when compiling those macros with their feature disabled. The explicit integer VM remains available in user mode even with `CW_ENABLE_ALL=0`; its execution semantics do not depend on the protection flags.

## Integer virtualization

Use `cloakwork::vm::make_program` for code you explicitly express as instructions. The VM has unsigned 64-bit registers, modular arithmetic, bitwise operations, rotation, comparison, and branches. It has no arbitrary memory access or native-call instruction.

```cpp
using cloakwork::vm::instruction;
using op = cloakwork::vm::opcode;

// Compute x * 2 + 5. Each instruction is {opcode, destination, a, b, immediate}.
static constexpr auto calculation = cloakwork::vm::make_program<CW_RANDOM_CT()>(std::array{
    instruction{op::argument, 0, 0, 0, 0},
    instruction{op::constant, 1, 0, 0, 2},
    instruction{op::mul, 0, 0, 1},
    instruction{op::constant, 1, 0, 0, 5},
    instruction{op::add, 0, 0, 1},
    instruction{op::ret, 0, 0}
});

auto answer = calculation.run(std::array{uint64_t{10}});
if (answer) consume(answer.value); // 25
```

The seed selects opcode numbering, register layout, and encoding masks for each instruction word. Programs are immutable and safe to run concurrently. Every run starts with zeroed registers and wipes its register array on exit. Opcode and register encodings are reversible, and decoded operands still exist during execution.

`make_program<Seed, Registers>` defaults to 8 registers; valid counts are powers of two from 1 through 256. All register fields must be in range, including unused fields. `constant` loads `immediate`; `argument` loads the argument at that index. Binary operations read registers `a` and `b` into `dst`. `move` copies `a`. `less` performs unsigned comparison and writes 0 or 1. `rotate_left` uses the low 6 bits of `b`. `jump` sets the instruction index to `immediate`; `jump_zero` does so when register `a` is zero. `ret` returns register `a`.

Construction rejects invalid opcodes, registers, branch targets, and programs without a return instruction at compile time. Unreachable returns are allowed, so runtime execution is bounded. `run(arguments, budget)` defaults to 100,000 instructions. The returned `result` contains `value`, `status`, and `steps`; check it before using `value`. Errors are `missing_argument`, `invalid_instruction`, and `step_limit`. Falling off the program is an error. Return instructions count toward the budget. This VM is not a security sandbox for hostile bytecode.

---

## Kernel Mode

I'd recommend you use my other library [Kernelcloak](https://github.com/ck0i/Kernelcloak) for kernel work, it is much more in depth and Cloakwork doesn't really suit kernel work as much as other libraries do. However, if you choose to still use Cloakwork, here you go:

Kernel mode is selected by `_KERNEL_MODE` or forced with `#define CW_KERNEL_MODE 1`. Include the WDK headers first. This path has not been validated by the current tests.

### Feature Availability

| Feature | Kernel Mode | Reason |
|---------|-------------|--------|
| Compile-time random | Enabled | Pure consteval |
| String hashing | Enabled | Pure consteval |
| Anti-debug | Enabled | Kernel-specific techniques |
| String encryption | No-op | Requires `atexit` for static destructors |
| Value obfuscation | No-op | Requires C++20 concepts / `std::bit_cast` |
| Control flow | No-op | Depends on value obfuscation |
| Function obfuscation | No-op | Requires C++20 concepts |
| Data hiding | No-op | Requires `std::unique_ptr` |
| Metamorphic | No-op | Requires `std::initializer_list` |
| Import hiding | No-op | PEB walking is usermode-only |
| Anti-VM | No-op | Uses usermode APIs |
| Integrity checks | No-op | Requires `VirtualQuery` |
| Syscalls | No-op | Already in kernel |

### Example

```cpp
#include <ntddk.h>
#define CW_KERNEL_MODE 1
#include "cloakwork.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    constexpr uint32_t hash = CW_HASH("NtClose");
    constexpr uint32_t key = CW_RANDOM_CT();

    if (cloakwork::anti_debug::comprehensive_check()) {
        KeBugCheckEx(0xDEAD, 0, 0, 0, 0);
    }

    return STATUS_SUCCESS;
}
```

### Kernel Anti-Debug Techniques

- **KdDebuggerEnabled** -- global flag set when kernel debugger is attached
- **KdDebuggerNotPresent** -- inverse flag (false = debugger present)
- **PsIsProcessBeingDebugged** -- per-process debug port check (dynamically resolved)
- **Debug registers** -- direct `__readdr()` intrinsic for DR0-DR3 hardware breakpoints
- **Timing analysis** -- `KeQueryPerformanceCounter` vs RDTSC for single-step detection

### Kernel Entropy Sources

Runtime random in kernel mode combines: `__rdtsc()`, `PsGetCurrentProcess()`/`PsGetCurrentThread()` (KASLR), process/thread IDs, `KeQueryPerformanceCounter()`, `KeQuerySystemTime()`, `KeQueryInterruptTime()`, pool allocation addresses, and stack addresses. Mixed via xorshift64*.

---

## Credits & License

- Inspired by [obfusheader.h](https://github.com/ac3ss0r/obfusheader.h), nimrodhide.h, qengine, and the anti-reverse-engineering community on unknowncheats.
- Created by helz.dev/Helzky | Discord: `ck0i`
- MIT License -- do what you want, no warranty.
