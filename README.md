# Cloakwork

Single-header C++20 obfuscation for Windows. Copy `cloakwork.h` into your project and include it. MSVC links the required Windows libraries automatically.

```cpp
#include "cloakwork.h"
```

See [demo.cpp](demo.cpp) for a complete, runnable example.

## Strings

```cpp
const char* text = CW_STR("config.toml");
const char* layered = CW_STR_LAYERED("session token");
const wchar_t* wide = CW_WSTR(L"wide text");

auto local = CW_STR_STACK("temporary plaintext");
consume(local.get());
```

`CW_STR`, `CW_STR_LAYERED`, and `CW_WSTR` return stable pointers. Their decoded text stays in memory after first use. `CW_STR_STACK` owns its buffer and wipes it when destroyed; keep it in a named variable.

## Values and arithmetic

```cpp
auto number = CW_INT(42);
number.set(CW_ADD(number.get(), 8));

auto encoded = CW_MBA(100);
auto changing = CW_POLY(1200);
changing.rekey();
auto scattered = CW_SCATTER(uint64_t{123});
cloakwork::rt_const<double> rate{0.25};
int constant = CW_CONST(42);
```

- Arithmetic: `CW_ADD(a, b)`, `CW_SUB(a, b)`, `CW_NEG(a)`.
- Bitwise: `CW_AND(a, b)`, `CW_OR(a, b)`, `CW_XOR(a, b)`.
- Comparisons: `CW_EQ`, `CW_NE`, `CW_LT`, `CW_GT`, `CW_LE`, `CW_GE`.
- Booleans: `CW_TRUE`, `CW_FALSE`, `CW_BOOL(expr)`, `cloakwork::obf_bool`.

Value wrappers support `.get()` and `.set()`; `rt_const<T>` exposes only `.get()` and conversion to `T`. `CW_SCATTER` accepts trivially copyable types. Arithmetic macros evaluate each operand once; integer addition, subtraction, and negation wrap at the result width.

`CW_CONST` encodes the entire arithmetic constant, including floating-point and Boolean representations, using the same block encoding as strings.

## Authenticated storage

```cpp
cloakwork::authenticated_value<uint64_t> balance{1200};
balance.set(1300);
uint64_t current = balance.get();

std::array<uint8_t, 3> input{1, 2, 3};
cloakwork::sealed_buffer buffer(input);
buffer.with_plaintext([](std::span<const uint8_t> bytes) { consume(bytes); });
```

These optional-use types require Windows 10 or later. They use CNG AES-256-GCM with a separate key per instance and 128-bit tags. Authentication failure throws `cloakwork::authentication_error` before the callback runs, regardless of the legacy detection-response setting. Provider failures throw; a failed update preserves the previous value. Instances cannot be copied or moved.

The callback's byte span is borrowed and wiped afterward, including on exceptions; do not retain it. `export_state()` and `import_state(packet)` support authenticated state restoration to the same live instance. Cross-instance imports fail; restoring an older authentic packet is allowed. Keys and verifier state must remain trusted. Each instance permits at most `2^32 - 1` seal attempts and buffers up to `ULONG_MAX` bytes.

## Calls and control flow

```cpp
auto wrapped = CW_CALL(my_function);
auto result = wrapped(arguments);

int doubled = CW_PROTECT(int, {
    return value * 2;
});

cloakwork::meta_func<int(int, int)> changing_call(add);
int sum = changing_call(19, 23);
```

Also available: `CW_FLATTEN(func, ...)`, `CW_PROTECT_VOID(body)`, `CW_IF(cond)` / `CW_ELSE`, `CW_BRANCH(cond)`, `CW_JUNK()`, and `CW_JUNK_FLOW()`.

`CW_PROTECT` wraps a native C++ body; it does not convert that body into VM instructions. For explicit integer virtualization, use `cloakwork::vm::make_program`; [demo.cpp](demo.cpp) includes a working program and result handling.

`CW_CALL` and metamorphic wrappers reject null functions. Metamorphic calls use Windows x64 executable thunks. Allocation or publication failures throw, as does calling a moved-from wrapper.

Combine protections through the shared wrapper:

```cpp
constexpr auto policy = cloakwork::call_protection::encoded | cloakwork::call_protection::integrity;
cloakwork::protected_function<int(int, int), policy> checked_add(add, known_code_size);
```

Add `call_protection::metamorphic` for changing x64 thunks. Requested protections must be enabled. Wrappers preserve reference returns, move-only arguments, and exception propagation. `CW_SPOOF_CALL` is now a compatibility alias for `CW_CALL`; it no longer edits return addresses or claims stack spoofing.

## Debugger and VM checks

```cpp
bool debugger = CW_CHECK_DEBUG();
bool virtual_machine = CW_CHECK_VM();

CW_ANTI_DEBUG();
CW_ANTI_VM();
```

The `CW_CHECK_*` macros only return a result. `CW_ANTI_DEBUG()` and `CW_ANTI_VM()` terminate on detection by default. Set `CW_ANTI_DEBUG_RESPONSE` before including the header:

- `0`: ignore detections.
- `1`: fail-fast, the default.
- `2`: legacy no-op.
- `3`: call `CW_DETECTION_CALLBACK(reason)`.

For a host-controlled response:

```cpp
namespace cloakwork { enum class detection_reason; }
void on_detection(cloakwork::detection_reason reason);

#define CW_ANTI_DEBUG_RESPONSE 3
#define CW_DETECTION_CALLBACK(reason) on_detection(reason)
#include "cloakwork.h"
```

Define `on_detection` in your application. Reasons are `debugger`, `virtual_machine`, and `integrity_failure`. Returning allows execution to continue; throwing or terminating stops it. The callback runs on the detecting thread and must support concurrent calls if your application uses them.

## Integrity checks

```cpp
auto checked = CW_INTEGRITY_CHECK(my_function, known_code_size);
bool intact = checked.verify();
auto result = checked(arguments);
```

Create the wrapper while the code is trusted and retain it for later calls. Supply a non-null function and a nonzero, readable byte range. Every call checks those bytes and uses the configured detection response on a mismatch. `.verify()` only returns a result.

Reference bytes live in read-only pages. For several regions, `integrity::snapshot::capture({region_a, region_b})` packs byte spans into a shared read-only allocation and returns snapshots. Pass a snapshot as the second argument to an integrity-enabled `protected_function`. Unreadable or empty capture ranges are rejected. Read-only storage does not eliminate verification/execution races or protect against an attacker who can change page protections and verifier code.

Other helpers: `CW_DETECT_HOOK(func)`, `CW_VERIFY_FUNCS(...)`, and `CW_COMPUTE_HASH(ptr, size)`.

## Imports, hashes, and random values

```cpp
auto get_pid = CW_IMPORT("kernel32.dll", GetCurrentProcessId);
if (get_pid) {
    DWORD pid = get_pid();
}

constexpr uint32_t name_hash = CW_HASH_CI("kernel32.dll");
constexpr auto build_value = CW_RANDOM_CT();
auto runtime_value = CW_RANDOM_RT();
int choice = CW_RAND_RT(1, 10);
```

- Imports: `CW_IMPORT_WIDE`, `CW_GET_MODULE(name)`, `CW_GET_PROC(module, func)`. Invalid images and unresolved or cyclic forwarders return `nullptr`; check pointers before calling.
- Hashing: `CW_HASH`, `CW_HASH_CI`, `CW_HASH_WIDE`, `CW_HASH_WIDE_CI`, `CW_HASH_RT`, `CW_HASH_RT_CI`.
- Random ranges: `CW_RAND_CT(min, max)` and `CW_RAND_RT(min, max)`, inclusive. Reversed bounds are rejected; distribution is not guaranteed uniform.
- Syscalls on x64: `CW_SYSCALL_NUMBER(NtClose)` and `CW_SYSCALL(NtClose, handle)`. Check the returned syscall number or status for failure. Thunk allocation or publication failures return `STATUS_UNSUCCESSFUL`. Published pages stay read/execute; replaced pages remain alive through active calls, and thread exit clears the cache.

With random support enabled, Windows user-mode runtime randomness uses the OS cryptographic provider and fails fast if it fails. Compile-time values use a deterministic build seed.

## Configuration

All features default to enabled. Set overrides before including `cloakwork.h` and use the same definitions in every translation unit:

```cpp
#define CW_BUILD_SEED 0x12AB34CDu
#define CW_ENABLE_ANTI_VM 0
#include "cloakwork.h"
```

`CW_ENABLE_ALL` sets the default for individual switches. Available suffixes for `CW_ENABLE_` are:

```text
STRING_ENCRYPTION    VALUE_OBFUSCATION    CONTROL_FLOW
ANTI_DEBUG          FUNCTION_OBFUSCATION DATA_HIDING
METAMORPHIC         COMPILE_TIME_RANDOM IMPORT_HIDING
SYSCALLS            ANTI_VM             INTEGRITY_CHECKS
```

Unsupported feature combinations produce compile-time errors. MSVC also rejects linked translation units with different seed, feature, or detection-response definitions. Disabled macros may return raw values instead of wrappers, so `.get()` is only available with the corresponding feature enabled. Rebuild all translation units after updating the header or configuration.

## Build the demo

Place `cloakwork.h` and `demo.cpp` in the same directory. From an x64 Visual Studio developer terminal with a recent MSVC toolset and Windows SDK:

```powershell
cl /std:c++20 /EHsc /O2 demo.cpp /Fe:cloakwork_demo.exe
.\cloakwork_demo.exe
```

## Release seeds

Set `CW_BUILD_SEED` to a chosen 32-bit value for each release. You can define it in your source before including the header or pass it to the compiler:

```powershell
cl /std:c++20 /EHsc /O2 /DCW_BUILD_SEED=0x12AB34CDu demo.cpp /Fe:cloakwork_demo.exe
```

Use identical definitions across translation units and record the seed with your release's source revision and build settings. Reusing them reproduces the compile-time diversification inputs. Exact binary reproduction also depends on source paths, toolchain, and linker settings.

For kernel work, use [Kernelcloak](https://github.com/ck0i/Kernelcloak). Cloakwork's limited kernel path requires WDK headers before this header.
