#ifndef CLOAKWORK_H
#define CLOAKWORK_H

// Cloakwork advanced obfuscation library - header-only c++20 implementation
// Comprehensive protection against static and dynamic analysis

// ██████╗██╗      ██████╗  █████╗ ██╗  ██╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
//██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
//██║     ██║     ██║   ██║███████║█████╔╝ ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
//██║     ██║     ██║   ██║██╔══██║██╔═██╗ ██║███╗██║██║   ██║██╔══██╗██╔═██╗
//╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
// ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

// Created by @helz.dev on Discord.
// Inspiration from obfusheader.h and Zapcrash's nimrodhide.h

// =================================================================
// COMPILE-TIME CONFIGURATION
// =================================================================
//
// Cloakwork can be configured at compile-time to include only the features you need.
// This reduces binary size and compilation time significantly.
//
// To disable a feature, define the corresponding macro as 0 before including this header:
//   #define CW_ENABLE_STRING_ENCRYPTION 0
//   #include "cloakwork.h"
//
// Alternatively, you can define them as compiler flags:
//   -DCW_ENABLE_METAMORPHIC=0
//
// By default, all features are enabled for backwards compatibility.
//
// Configuration options:
// ----------------------
// CW_ENABLE_ALL                    - master switch to enable/disable everything (default: 1)
// CW_ENABLE_STRING_ENCRYPTION      - compile-time string encryption (default: 1)
// CW_ENABLE_VALUE_OBFUSCATION      - integer/value obfuscation (default: 1)
// CW_ENABLE_CONTROL_FLOW           - control flow obfuscation (default: 1)
// CW_ENABLE_ANTI_DEBUG             - anti-debugging features (default: 1)
// CW_ENABLE_FUNCTION_OBFUSCATION   - function pointer obfuscation (default: 1)
// CW_ENABLE_DATA_HIDING            - scattered/polymorphic values (default: 1)
// CW_ENABLE_METAMORPHIC            - metamorphic code generation (default: 1)
// CW_ENABLE_COMPILE_TIME_RANDOM    - compile-time random generation (default: 1)
// CW_ENABLE_IMPORT_HIDING          - dynamic API resolution / import hiding (default: 1)
// CW_ENABLE_SYSCALLS               - direct syscall invocation (default: 1)
// CW_ENABLE_ANTI_VM                - anti-VM/sandbox detection (default: 1)
// CW_ENABLE_INTEGRITY_CHECKS       - self-integrity verification (default: 1)
// CW_ANTI_DEBUG_RESPONSE           - response to debugger detection: 0=ignore, 1=crash, 2=fake (default: 1)
//
// KERNEL MODE SUPPORT:
// --------------------
// CW_KERNEL_MODE                   - enable kernel mode compatibility (default: auto-detect)
//
// Kernel mode is auto-detected via _KERNEL_MODE or NTDDI_VERSION macros.
// You can also force kernel mode with: #define CW_KERNEL_MODE 1
//
// In kernel mode:
//   - STL containers (vector, mutex, atomic) are replaced with kernel-safe alternatives
//   - Heap operations use ExAllocatePool2/ExFreePool instead of new/malloc
//   - Anti-debug uses kernel structures (EPROCESS, ETHREAD)
//   - Import hiding walks DriverSection linked list
//   - Syscalls are disabled (already in kernel)
//   - Thread-safety uses spinlocks instead of std::mutex
//
// Kernel mode usage:
// ------------------
// #include <ntddk.h>
// #define CW_KERNEL_MODE 1  // optional, auto-detected if ntddk.h included
// #include "cloakwork.h"
//
// Minimal configuration example:
// ------------------------------
// #define CW_ENABLE_ALL 0                      // disable everything first
// #define CW_ENABLE_STRING_ENCRYPTION 1        // enable only what you need
// #define CW_ENABLE_VALUE_OBFUSCATION 1
// #include "cloakwork.h"
//
// Performance-focused configuration:
// -----------------------------------
// #define CW_ENABLE_METAMORPHIC 0              // disable heavy features
// #include "cloakwork.h"
//
// =================================================================

#ifndef CW_KERNEL_MODE
    #if defined(_KERNEL_MODE)
        #define CW_KERNEL_MODE 1
    #else
        #define CW_KERNEL_MODE 0
    #endif
#endif

#if CW_KERNEL_MODE
    // syscalls don't make sense in kernel mode
    #ifdef CW_ENABLE_SYSCALLS
        #undef CW_ENABLE_SYSCALLS
    #endif
    #define CW_ENABLE_SYSCALLS 0

    // std::unique_ptr not available in kernel
    #ifdef CW_ENABLE_DATA_HIDING
        #undef CW_ENABLE_DATA_HIDING
    #endif
    #define CW_ENABLE_DATA_HIDING 0

    // std::initializer_list not available
    #ifdef CW_ENABLE_METAMORPHIC
        #undef CW_ENABLE_METAMORPHIC
    #endif
    #define CW_ENABLE_METAMORPHIC 0

    // static destructors need atexit
    #ifdef CW_ENABLE_STRING_ENCRYPTION
        #undef CW_ENABLE_STRING_ENCRYPTION
    #endif
    #define CW_ENABLE_STRING_ENCRYPTION 0

    // needs C++20 concepts and std::bit_cast
    #ifdef CW_ENABLE_VALUE_OBFUSCATION
        #undef CW_ENABLE_VALUE_OBFUSCATION
    #endif
    #define CW_ENABLE_VALUE_OBFUSCATION 0

    // PEB walking needs different impl in kernel
    #ifdef CW_ENABLE_IMPORT_HIDING
        #undef CW_ENABLE_IMPORT_HIDING
    #endif
    #define CW_ENABLE_IMPORT_HIDING 0

    // requires usermode APIs
    #ifdef CW_ENABLE_ANTI_VM
        #undef CW_ENABLE_ANTI_VM
    #endif
    #define CW_ENABLE_ANTI_VM 0

    // requires VirtualQuery
    #ifdef CW_ENABLE_INTEGRITY_CHECKS
        #undef CW_ENABLE_INTEGRITY_CHECKS
    #endif
    #define CW_ENABLE_INTEGRITY_CHECKS 0

    // needs concepts
    #ifdef CW_ENABLE_FUNCTION_OBFUSCATION
        #undef CW_ENABLE_FUNCTION_OBFUSCATION
    #endif
    #define CW_ENABLE_FUNCTION_OBFUSCATION 0

    // depends on value obfuscation (mba)
    #ifdef CW_ENABLE_CONTROL_FLOW
        #undef CW_ENABLE_CONTROL_FLOW
    #endif
    #define CW_ENABLE_CONTROL_FLOW 0
#endif

#ifndef CW_ENABLE_ALL
    #define CW_ENABLE_ALL 1
#endif

#ifndef CW_ENABLE_COMPILE_TIME_RANDOM
    #define CW_ENABLE_COMPILE_TIME_RANDOM CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_STRING_ENCRYPTION
    #define CW_ENABLE_STRING_ENCRYPTION CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_VALUE_OBFUSCATION
    #define CW_ENABLE_VALUE_OBFUSCATION CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_CONTROL_FLOW
    #define CW_ENABLE_CONTROL_FLOW CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_ANTI_DEBUG
    #define CW_ENABLE_ANTI_DEBUG CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_FUNCTION_OBFUSCATION
    #define CW_ENABLE_FUNCTION_OBFUSCATION CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_DATA_HIDING
    #define CW_ENABLE_DATA_HIDING CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_METAMORPHIC
    #define CW_ENABLE_METAMORPHIC CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_IMPORT_HIDING
    #define CW_ENABLE_IMPORT_HIDING CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_SYSCALLS
    #define CW_ENABLE_SYSCALLS CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_ANTI_VM
    #define CW_ENABLE_ANTI_VM CW_ENABLE_ALL
#endif

#ifndef CW_ENABLE_INTEGRITY_CHECKS
    #define CW_ENABLE_INTEGRITY_CHECKS CW_ENABLE_ALL
#endif

#ifndef CW_ANTI_DEBUG_RESPONSE
    #define CW_ANTI_DEBUG_RESPONSE 1  // 0=ignore, 1=crash, 2=fake data
#endif

#if CW_ENABLE_DATA_HIDING && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_DATA_HIDING requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_CONTROL_FLOW && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_CONTROL_FLOW requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_KERNEL_MODE
    #ifndef _NTDDK_
        #error "In kernel mode, include <ntddk.h> before cloakwork.h"
    #endif

    #include <intrin.h>

    extern "C" {
        NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
    }

    // define _fltused to satisfy linker when floating point is used
    // selectany allows multiple definitions across translation units
    extern "C" __declspec(selectany) int _fltused = 0;

    // WDK doesn't ship usermode STL headers
    using int8_t = signed char;
    using int16_t = short;
    using int32_t = int;
    using int64_t = long long;
    using uint8_t = unsigned char;
    using uint16_t = unsigned short;
    using uint32_t = unsigned int;
    using uint64_t = unsigned long long;
    using size_t = SIZE_T;
    using ptrdiff_t = SSIZE_T;

    namespace std {
        template<typename T, size_t N>
        struct array {
            T _data[N];

            constexpr T& operator[](size_t i) { return _data[i]; }
            constexpr const T& operator[](size_t i) const { return _data[i]; }
            constexpr T* data() { return _data; }
            constexpr const T* data() const { return _data; }
            constexpr size_t size() const { return N; }
        };

        template<typename T>
        constexpr T rotl(T value, int shift) {
            constexpr int bits = sizeof(T) * 8;
            shift &= (bits - 1);
            if (shift == 0) return value;
            return (value << shift) | (value >> (bits - shift));
        }

        template<typename T>
        constexpr T rotr(T value, int shift) {
            constexpr int bits = sizeof(T) * 8;
            shift &= (bits - 1);
            if (shift == 0) return value;
            return (value >> shift) | (value << (bits - shift));
        }

        template<size_t... Is>
        struct index_sequence {};

        template<size_t N, size_t... Is>
        struct make_index_sequence_impl : make_index_sequence_impl<N - 1, N - 1, Is...> {};

        template<size_t... Is>
        struct make_index_sequence_impl<0, Is...> {
            using type = index_sequence<Is...>;
        };

        template<size_t N>
        using make_index_sequence = typename make_index_sequence_impl<N>::type;

        template<bool B, class T = void>
        struct enable_if {};

        template<class T>
        struct enable_if<true, T> { using type = T; };

        template<bool B, class T = void>
        using enable_if_t = typename enable_if<B, T>::type;

        template<class T, class U>
        struct is_same { static constexpr bool value = false; };

        template<class T>
        struct is_same<T, T> { static constexpr bool value = true; };

        template<class T, class U>
        inline constexpr bool is_same_v = is_same<T, U>::value;

        template<class T>
        struct remove_cv { using type = T; };
        template<class T>
        struct remove_cv<const T> { using type = T; };
        template<class T>
        struct remove_cv<volatile T> { using type = T; };
        template<class T>
        struct remove_cv<const volatile T> { using type = T; };

        template<class T>
        using remove_cv_t = typename remove_cv<T>::type;

        template<class T>
        struct remove_reference { using type = T; };
        template<class T>
        struct remove_reference<T&> { using type = T; };
        template<class T>
        struct remove_reference<T&&> { using type = T; };

        template<class T>
        using remove_reference_t = typename remove_reference<T>::type;

        template<class T>
        struct is_integral { static constexpr bool value = false; };
        template<> struct is_integral<bool> { static constexpr bool value = true; };
        template<> struct is_integral<char> { static constexpr bool value = true; };
        template<> struct is_integral<signed char> { static constexpr bool value = true; };
        template<> struct is_integral<unsigned char> { static constexpr bool value = true; };
        // wchar_t is unsigned short in kernel mode with /Zc:wchar_t-, skip to avoid duplicate
        template<> struct is_integral<short> { static constexpr bool value = true; };
        template<> struct is_integral<unsigned short> { static constexpr bool value = true; };
        template<> struct is_integral<int> { static constexpr bool value = true; };
        template<> struct is_integral<unsigned int> { static constexpr bool value = true; };
        template<> struct is_integral<long> { static constexpr bool value = true; };
        template<> struct is_integral<unsigned long> { static constexpr bool value = true; };
        template<> struct is_integral<long long> { static constexpr bool value = true; };
        template<> struct is_integral<unsigned long long> { static constexpr bool value = true; };

        template<class T>
        inline constexpr bool is_integral_v = is_integral<remove_cv_t<T>>::value;

        template<class T>
        struct is_floating_point { static constexpr bool value = false; };
        template<> struct is_floating_point<float> { static constexpr bool value = true; };
        template<> struct is_floating_point<double> { static constexpr bool value = true; };
        template<> struct is_floating_point<long double> { static constexpr bool value = true; };

        template<class T>
        inline constexpr bool is_floating_point_v = is_floating_point<remove_cv_t<T>>::value;

        template<class T>
        struct is_arithmetic { static constexpr bool value = is_integral_v<T> || is_floating_point_v<T>; };

        template<class T>
        inline constexpr bool is_arithmetic_v = is_arithmetic<T>::value;

        template<class T>
        struct is_pointer { static constexpr bool value = false; };
        template<class T>
        struct is_pointer<T*> { static constexpr bool value = true; };
        template<class T>
        struct is_pointer<T* const> { static constexpr bool value = true; };
        template<class T>
        struct is_pointer<T* volatile> { static constexpr bool value = true; };
        template<class T>
        struct is_pointer<T* const volatile> { static constexpr bool value = true; };

        template<class T>
        inline constexpr bool is_pointer_v = is_pointer<T>::value;

        template<class T>
        T&& declval() noexcept;

        template<class T>
        constexpr T&& forward(remove_reference_t<T>& t) noexcept {
            return static_cast<T&&>(t);
        }

        template<class T>
        constexpr T&& forward(remove_reference_t<T>&& t) noexcept {
            return static_cast<T&&>(t);
        }

        template<class T>
        constexpr remove_reference_t<T>&& move(T&& t) noexcept {
            return static_cast<remove_reference_t<T>&&>(t);
        }
    }

    namespace cloakwork_internal {
        class kernel_spinlock {
        private:
            KSPIN_LOCK lock;
            KIRQL old_irql;

        public:
            kernel_spinlock() {
                KeInitializeSpinLock(&lock);
            }

            void acquire() {
                KeAcquireSpinLock(&lock, &old_irql);
            }

            void release() {
                KeReleaseSpinLock(&lock, old_irql);
            }
        };

        class spinlock_guard {
        private:
            kernel_spinlock& lock;
        public:
            spinlock_guard(kernel_spinlock& l) : lock(l) { lock.acquire(); }
            ~spinlock_guard() { lock.release(); }
            spinlock_guard(const spinlock_guard&) = delete;
            spinlock_guard& operator=(const spinlock_guard&) = delete;
        };

        template<typename T>
        class kernel_atomic {
        private:
            volatile T value;

        public:
            kernel_atomic() : value{} {}
            kernel_atomic(T val) : value(val) {}

            T load(int = 0) const {
                MemoryBarrier();
                return value;
            }

            void store(T val, int = 0) {
                value = val;
                MemoryBarrier();
            }

            T fetch_add(T val, int = 0) {
                if constexpr (sizeof(T) == 4) {
                    return static_cast<T>(InterlockedExchangeAdd(
                        reinterpret_cast<volatile LONG*>(&value),
                        static_cast<LONG>(val)));
                } else if constexpr (sizeof(T) == 8) {
                    return static_cast<T>(InterlockedExchangeAdd64(
                        reinterpret_cast<volatile LONG64*>(&value),
                        static_cast<LONG64>(val)));
                } else {
                    T old = value;
                    value += val;
                    return old;
                }
            }

            T operator++() {
                return fetch_add(1) + 1;
            }

            T operator++(int) {
                return fetch_add(1);
            }
        };

        inline void* kernel_alloc(size_t size) {
            // use NonPagedPoolNx for security (no-execute)
            return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'kwlC');
        }

        inline void kernel_free(void* ptr) {
            if (ptr) {
                ExFreePoolWithTag(ptr, 'kwlC');
            }
        }

        // different layout than the usermode PEB version
        struct KLDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            PVOID ExceptionTable;
            ULONG ExceptionTableSize;
            PVOID GpValue;
            PVOID NonPagedDebugInfo;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
            USHORT LoadCount;
            USHORT __Unused;
            PVOID SectionPointer;
            ULONG CheckSum;
            ULONG TimeDateStamp;
        };
    }

    #define CW_ATOMIC(T) cloakwork_internal::kernel_atomic<T>
    #define CW_MUTEX cloakwork_internal::kernel_spinlock
    #define CW_LOCK_GUARD(m) cloakwork_internal::spinlock_guard _cw_guard(m)
    #define CW_MO_RELAXED 0

#else
    #include <array>
    #include <vector>
    #include <algorithm>
    #include <atomic>
    #include <mutex>
    #include <memory>
    #include <bit>

    #ifdef _WIN32
        #include <windows.h>
        #include <intrin.h>
        #include <winternl.h>
        #include <tlhelp32.h>
        #include <iphlpapi.h>
        #pragma comment(lib, "iphlpapi.lib")

        // full LDR_DATA_TABLE_ENTRY structure (winternl.h has incomplete definition, fuck those guys)
        namespace cloakwork_internal {
            struct CW_LDR_DATA_TABLE_ENTRY {
                LIST_ENTRY InLoadOrderLinks;
                LIST_ENTRY InMemoryOrderLinks;
                LIST_ENTRY InInitializationOrderLinks;
                PVOID DllBase;
                PVOID EntryPoint;
                ULONG SizeOfImage;
                UNICODE_STRING FullDllName;
                UNICODE_STRING BaseDllName;
                ULONG Flags;
                USHORT LoadCount;
                USHORT TlsIndex;
                union {
                    LIST_ENTRY HashLinks;
                    struct {
                        PVOID SectionPointer;
                        ULONG CheckSum;
                    };
                };
                union {
                    ULONG TimeDateStamp;
                    PVOID LoadedImports;
                };
                PVOID EntryPointActivationContext;
                PVOID PatchInformation;
            };
        }
    #endif

    #define CW_ATOMIC(T) std::atomic<T>
    #define CW_MUTEX std::mutex
    #define CW_LOCK_GUARD(m) std::lock_guard<std::mutex> _cw_guard(m)
    #define CW_MO_RELAXED std::memory_order_relaxed

#endif // CW_KERNEL_MODE

#ifdef _MSC_VER
    #define CW_FORCEINLINE __forceinline
    #define CW_NOINLINE __declspec(noinline)
    #define CW_SECTION(x) __declspec(allocate(x))
    #define CW_COMPILER_BARRIER() _ReadWriteBarrier()
    // optimization barriers - prevents LTCG/WPO from seeing through obfuscation
    #define CW_OPT_OFF __pragma(optimize("", off))
    #define CW_OPT_ON __pragma(optimize("", on))
    #pragma warning(push)
    #pragma warning(disable: 4996 4244 4267)
#elif defined(__GNUC__) || defined(__clang__)
    #define CW_FORCEINLINE __attribute__((always_inline)) inline
    #define CW_NOINLINE __attribute__((noinline))
    #define CW_SECTION(x) __attribute__((section(x)))
    #define CW_COMPILER_BARRIER() asm volatile("" ::: "memory")
    #define CW_OPT_OFF _Pragma("GCC push_options") _Pragma("GCC optimize(\"O0\")")
    #define CW_OPT_ON _Pragma("GCC pop_options")
#else
    #define CW_FORCEINLINE inline
    #define CW_NOINLINE
    #define CW_SECTION(x)
    #define CW_COMPILER_BARRIER() std::atomic_signal_fence(std::memory_order_seq_cst)
    #define CW_OPT_OFF
    #define CW_OPT_ON
#endif

// =================================================================
// CLOAKWORK QUICK REFERENCE WIKI
// =================================================================
//
// STRING ENCRYPTION
// -----------------
// CW_STR("text")                   - encrypts string at compile-time, decrypts at runtime
//                                    usage: const char* msg = CW_STR("secret message");
//
// CW_STR_LAYERED("text")           - multi-layer encrypted string with polymorphic re-encryption
//                                    usage: const char* msg = CW_STR_LAYERED("secret");
//
// CW_STR_STACK("text")              - stack-based encrypted string (auto-cleanup)
//                                    usage: auto msg = CW_STR_STACK("secret");
//
// INTEGER/VALUE OBFUSCATION
// -------------------------
// CW_INT(value)                    - obfuscates integer/numeric values
//                                    usage: int x = CW_INT(42);
//
// CW_ADD(a, b)                     - obfuscated addition using MBA
//                                    usage: int sum = CW_ADD(x, y);
//
// CW_SUB(a, b)                     - obfuscated subtraction using MBA
//                                    usage: int diff = CW_SUB(x, y);
//
// CW_SCATTER(value)                - scatters data across memory chunks
//                                    usage: auto scattered = CW_SCATTER(myStruct);
//
// CW_POLY(value)                   - creates polymorphic value that mutates internally
//                                    usage: auto poly = CW_POLY(100);
//
// BOOLEAN OBFUSCATION
// -------------------
// CW_TRUE                          - obfuscated true using opaque predicates
//                                    usage: if (CW_TRUE) { /* always executes */ }
//
// CW_FALSE                         - obfuscated false using opaque predicates
//                                    usage: if (CW_FALSE) { /* never executes */ }
//
// CW_BOOL(expr)                    - obfuscates a boolean expression
//                                    usage: bool result = CW_BOOL(x > 0);
//
// obfuscated_bool                  - class for storing obfuscated boolean values
//                                    usage: obfuscated_bool flag(true);
//
// obfuscated_value<T>              - template class for obfuscating any value type
//                                    usage: obfuscated_value<int> val(42);
//
// mba_obfuscated<T>                - mixed boolean arithmetic obfuscation
//                                    usage: mba_obfuscated<int> val(42);
//
// CONTROL FLOW OBFUSCATION
// ------------------------
// CW_IF(condition)                 - obfuscated if statement with opaque predicates
//                                    usage: CW_IF(x > 0) { /* code */ }
//
// CW_ELSE                          - obfuscated else clause
//                                    usage: CW_IF(cond) { } CW_ELSE { }
//
// CW_BRANCH(condition)             - indirect branching with obfuscation
//                                    usage: CW_BRANCH(isValid) { /* code */ }
//
// CW_FLATTEN(func, args...)        - flattens control flow via state machine
//                                    usage: auto result = CW_FLATTEN(myFunc, arg1, arg2);
//
// CFG FLATTENING (block-level state machine)
// -------------------------------------------
// CW_FLAT_FUNC(ret_type)           - begin flattened function returning ret_type
//                                    usage: auto r = CW_FLAT_FUNC(int) ... CW_FLAT_END;
//
// CW_FLAT_VOID                     - begin void flattened function
//                                    usage: CW_FLAT_VOID ... CW_FLAT_VOID_END;
//
// CW_FLAT_VARS(...)                - declare shared variables across blocks
//                                    usage: CW_FLAT_VARS(int x = 0; int y = 0;)
//
// CW_FLAT_ENTRY(id)                - set entry block ID
//                                    usage: CW_FLAT_ENTRY(0)
//
// CW_FLAT_BEGIN                    - begin dispatch loop (auto-inserts dead blocks)
//
// CW_FLAT_BLOCK(id)                - start a block with given ID
//                                    usage: CW_FLAT_BLOCK(0) x = 42; CW_FLAT_GOTO(1)
//
// CW_FLAT_GOTO(id)                 - unconditional jump to block
//                                    usage: CW_FLAT_GOTO(1)
//
// CW_FLAT_GOTO_OBF(id)             - obfuscated jump (adds fake dead-block branch)
//                                    usage: CW_FLAT_GOTO_OBF(1)
//
// CW_FLAT_IF(cond, true_id, false_id) - conditional branch
//                                    usage: CW_FLAT_IF(x > 0, 2, 3)
//
// CW_FLAT_IF_OBF(cond, t, f)       - obfuscated conditional (volatile + opaque pred)
//                                    usage: CW_FLAT_IF_OBF(x > 0, 2, 3)
//
// CW_FLAT_RETURN(val)              - return value and exit
//                                    usage: CW_FLAT_RETURN(x * 2)
//
// CW_FLAT_EXIT()                   - exit without return value
//                                    usage: CW_FLAT_EXIT()
//
// CW_FLAT_SWITCH2..4(expr, ...)    - multi-way dispatch (2-4 cases + default)
//                                    usage: CW_FLAT_SWITCH3(cmd, 0,blk_a, 1,blk_b, 2,blk_c, blk_def)
//
// CW_FLAT_END                      - close dispatch loop (non-void)
// CW_FLAT_VOID_END                 - close dispatch loop (void)
//
// SIMPLIFIED CFG PROTECTION (automatic state machine wrapping)
// -------------------------------------------------------------
// CW_PROTECT(ret_type, body)        - wraps code in encrypted state machine, returns ret_type
//                                    usage: int r = CW_PROTECT(int, { return x * 2; });
//
// CW_PROTECT_VOID(body)             - wraps void code in encrypted state machine
//                                    usage: CW_PROTECT_VOID({ do_work(); });
//
// FUNCTION CALL PROTECTION
// ------------------------
// CW_CALL(function)                - obfuscates function pointer and adds anti-debug
//                                    usage: auto obf_func = CW_CALL(originalFunc);
//                                           obf_func(args);
//
// obfuscated_call<Func>            - template class for function pointer obfuscation
//                                    usage: obfuscated_call<decltype(func)> obf{func};
//
// ANTI-DEBUGGING/ANALYSIS
// -----------------------
// CW_ANTI_DEBUG()                  - crashes if debugger detected (comprehensive checks)
//                                    usage: CW_ANTI_DEBUG();
//
// CW_CHECK_ANALYSIS()              - comprehensive check for debuggers/analysis tools
//                                    usage: CW_CHECK_ANALYSIS();
//
// CW_INLINE_CHECK()                - inline anti-debug check (scatter these throughout code)
//                                    usage: CW_INLINE_CHECK();
//
// anti_debug::is_debugger_present() - returns true if debugger detected (basic checks)
//                                     usage: if(anti_debug::is_debugger_present()) { }
//
// anti_debug::comprehensive_check() - advanced multi-layered debugger detection
//                                     usage: if(anti_debug::comprehensive_check()) { }
//
// anti_debug::timing_check(func)   - detects debuggers via timing analysis
//                                    usage: if(timing_check([](){}, 1000)) { }
//
// anti_debug::verify_code_integrity() - checks if code has been modified
//                                       usage: if(!verify_code_integrity(func, size)) { }
//
// COMPILE-TIME RANDOMIZATION
// --------------------------
// CW_RANDOM_CT()                   - generates compile-time random value (unique per build)
//                                    usage: constexpr auto rand = CW_RANDOM_CT();
//
// CW_RANDOM_RT()                   - generates runtime random value (unique per execution)
//                                    usage: uint64_t rand = CW_RANDOM_RT();
//
// CW_RAND_CT(min, max)             - compile-time random in range [min, max]
//                                    usage: constexpr int x = CW_RAND_CT(1, 100);
//
// CW_RAND_RT(min, max)             - runtime random in range [min, max]
//                                    usage: int x = CW_RAND_RT(1, 100);
//
// WIDE STRING ENCRYPTION
// ----------------------
// CW_WSTR(L"text")                  - encrypts wide string at compile-time
//                                    usage: const wchar_t* msg = CW_WSTR(L"secret");
//
// STRING HASHING
// --------------
// CW_HASH("text")                   - compile-time FNV-1a hash of string (case-sensitive)
//                                    usage: constexpr uint32_t h = CW_HASH("NtClose");
//
// CW_HASH_CI("text")                - compile-time case-insensitive hash (for module names)
//                                    usage: constexpr uint32_t h = CW_HASH_CI("kernel32.dll");
//
// CW_HASH_WIDE(L"text")             - compile-time hash of wide string
//                                    usage: constexpr uint32_t h = CW_HASH_WIDE(L"ntdll.dll");
//
// hash::fnv1a_runtime(str)          - runtime hash of string
//                                    usage: uint32_t h = hash::fnv1a_runtime(dynamicStr);
//
// IMPORT HIDING
// -------------
// CW_IMPORT(mod, func)              - resolve function without import table
//                                    usage: auto pFunc = CW_IMPORT("kernel32.dll", VirtualAlloc);
//
// imports::getModuleBase(hash)      - get module base by hash
//                                    usage: void* ntdll = imports::getModuleBase(CW_HASH("ntdll.dll"));
//
// imports::getProcAddress(mod, hash) - get function by hash
//                                     usage: void* func = imports::getProcAddress(mod, CW_HASH("NtClose"));
//
// DIRECT SYSCALLS
// ---------------
// CW_SYSCALL_NUMBER(func)           - get syscall number for ntdll function
//                                    usage: uint32_t num = CW_SYSCALL_NUMBER(NtClose);
//
// syscall::getSyscallNumber(hash)   - get syscall number by function hash
//                                    usage: uint32_t num = syscall::getSyscallNumber(CW_HASH("NtClose"));
//
// ANTI-VM/SANDBOX DETECTION
// -------------------------
// CW_ANTI_VM()                      - crashes if VM/sandbox detected
//                                    usage: CW_ANTI_VM();
//
// CW_CHECK_VM()                     - returns true if VM/sandbox detected
//                                    usage: if(CW_CHECK_VM()) { /* in VM */ }
//
// anti_vm::comprehensive_check()    - comprehensive VM/sandbox detection
//                                    usage: if(anti_debug::anti_vm::comprehensive_check()) { }
//
// OBFUSCATED COMPARISONS
// ----------------------
// CW_EQ(a, b)                       - obfuscated equality check (a == b)
//                                    usage: if(CW_EQ(x, 42)) { }
//
// CW_NE(a, b)                       - obfuscated not-equals (a != b)
// CW_LT(a, b)                       - obfuscated less-than (a < b)
// CW_GT(a, b)                       - obfuscated greater-than (a > b)
// CW_LE(a, b)                       - obfuscated less-or-equal (a <= b)
// CW_GE(a, b)                       - obfuscated greater-or-equal (a >= b)
//
// ENCRYPTED CONSTANTS
// -------------------
// CW_CONST(value)                   - encrypted compile-time constant
//                                    usage: int x = CW_CONST(0xDEADBEEF);
//
// constants::runtime_constant<T>    - runtime-keyed constant (unique per execution)
//                                    usage: runtime_constant<int> val(42);
//
// JUNK CODE INSERTION
// -------------------
// CW_JUNK()                         - insert junk computation
//                                    usage: CW_JUNK();
//
// CW_JUNK_FLOW()                    - insert junk with fake control flow
//                                    usage: CW_JUNK_FLOW();
//
// RETURN ADDRESS SPOOFING
// -----------------------
// CW_SPOOF_CALL(func)               - call with spoofed return address
//                                    usage: auto spoof = CW_SPOOF_CALL(myFunc);
//
// spoof::getRetGadget()             - get cached ret gadget for spoofing
//                                    usage: void* gadget = spoof::getRetGadget();
//
// INTEGRITY VERIFICATION
// ----------------------
// CW_INTEGRITY_CHECK(func, size)    - wrap function with integrity checking
//                                    usage: auto checked = CW_INTEGRITY_CHECK(myFunc, 64);
//
// CW_DETECT_HOOK(func)              - check if function is hooked
//                                    usage: if(CW_DETECT_HOOK(VirtualAlloc)) { /* hooked */ }
//
// integrity::computeHash(data, size) - compute hash of memory region
//                                     usage: uint32_t h = integrity::computeHash(ptr, 100);
//
// integrity::verifyFunctions(...)   - verify multiple functions at once
//                                    usage: if(!integrity::verifyFunctions(f1, f2)) { }
//
// CONVENIENCE MACROS & TYPE ALIASES
// ----------------------------------
// CW_IS_DEBUGGED()                  - is_debugger_present() (PEB + NtGlobalFlag)
// CW_HAS_HWBP()                    - has_hardware_breakpoints() (DR0-DR3)
// CW_CHECK_DEBUG()                  - comprehensive_check() (all anti-debug combined)
// CW_DETECT_HIDING()               - detect anti-anti-debug tools (ScyllaHide etc.)
// CW_DETECT_PARENT()               - check if parent is a debugger
// CW_DETECT_KERNEL_DBG()           - kernel debugger detection
// CW_TIMING_CHECK()                - rdtsc vs QPC timing check
// CW_DETECT_DBG_ARTIFACTS()        - debugger registry artifacts
// CW_DETECT_HYPERVISOR()           - hypervisor present (CPUID)
// CW_DETECT_VM_VENDOR()            - VM vendor string detection
// CW_DETECT_LOW_RESOURCES()        - low CPU/RAM (sandbox indicator)
// CW_DETECT_SANDBOX_DLLS()         - sandbox DLL detection
// CW_GET_MODULE(name)              - getModuleBase via PEB walk (string → hash)
//                                    usage: void* ntdll = CW_GET_MODULE("ntdll.dll");
// CW_GET_PROC(mod, func)           - getProcAddress via export walk (string → hash)
//                                    usage: void* fn = CW_GET_PROC(ntdll, "NtClose");
// CW_HASH_RT(str)                  - runtime FNV-1a hash (case-sensitive)
// CW_HASH_RT_CI(str)               - runtime FNV-1a hash (case-insensitive)
// CW_COMPUTE_HASH(ptr, size)       - compute hash of memory region
// CW_VERIFY_FUNCS(...)             - verify multiple functions aren't hooked
// CW_RET_GADGET()                  - get cached ret gadget for return address spoofing
// CW_NEG(a)                        - obfuscated negation using MBA (~x + 1)
//
// Type aliases (in cloakwork namespace):
// cloakwork::obf_bool               - shorthand for obfuscated_bool
// cloakwork::meta_func<Sig>         - shorthand for metamorphic_function<Sig>
// cloakwork::rt_const<T>            - shorthand for runtime_constant<T>
//
// =================================================================

namespace cloakwork {

#if CW_ENABLE_COMPILE_TIME_RANDOM
    namespace detail {
        template<size_t N>
        constexpr uint32_t fnv1a_hash(const char (&str)[N], uint32_t basis = 0x811c9dc5) {
            uint32_t hash = basis;
            for(size_t i = 0; i < N-1; ++i) {
                hash ^= static_cast<uint32_t>(str[i]);
                hash *= 0x01000193;
            }
            return hash;
        }

        inline bool try_hardware_random(uint64_t& out) {
#ifdef _WIN32
#ifdef __RDSEED__
            if (_rdseed64_step(reinterpret_cast<unsigned long long*>(&out))) {
                return true;
            }
#endif
#endif
            return false;
        }

        // not cryptographic - just makes runtime keys unique per execution
        // to frustrate static analysis
        inline uint64_t runtime_entropy_seed() {
            uint64_t entropy = 0;

            if (try_hardware_random(entropy)) {
                return entropy;
            }

#if CW_KERNEL_MODE
            entropy ^= __rdtsc();

            // kaslr makes these different per boot
            entropy ^= reinterpret_cast<uint64_t>(PsGetCurrentProcess());
            entropy ^= reinterpret_cast<uint64_t>(PsGetCurrentThread());
            entropy ^= static_cast<uint64_t>(HandleToULong(PsGetCurrentProcessId())) << 32;
            entropy ^= static_cast<uint64_t>(HandleToULong(PsGetCurrentThreadId()));

            volatile char stack_var;
            entropy ^= reinterpret_cast<uint64_t>(&stack_var);

            LARGE_INTEGER perf_counter;
            perf_counter = KeQueryPerformanceCounter(nullptr);
            entropy ^= static_cast<uint64_t>(perf_counter.QuadPart);

            LARGE_INTEGER system_time;
            KeQuerySystemTime(&system_time);
            entropy ^= static_cast<uint64_t>(system_time.QuadPart);

            entropy ^= static_cast<uint64_t>(KeQueryInterruptTime());

            void* pool_alloc = cloakwork_internal::kernel_alloc(16);
            if (pool_alloc) {
                entropy ^= reinterpret_cast<uint64_t>(pool_alloc);
                cloakwork_internal::kernel_free(pool_alloc);
            }

#elif defined(_WIN32)
            entropy ^= __rdtsc();

            // aslr makes these different per run
            entropy ^= static_cast<uint64_t>(GetCurrentProcessId()) << 32;
            entropy ^= static_cast<uint64_t>(GetCurrentThreadId());

            volatile char stack_var;
            entropy ^= reinterpret_cast<uint64_t>(&stack_var);

            HMODULE module = GetModuleHandleA(nullptr);
            entropy ^= reinterpret_cast<uint64_t>(module);

            LARGE_INTEGER perf_counter;
            QueryPerformanceCounter(&perf_counter);
            entropy ^= static_cast<uint64_t>(perf_counter.QuadPart);

            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            entropy ^= (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

            void* heap_alloc = HeapAlloc(GetProcessHeap(), 0, 16);
            if (heap_alloc) {
                entropy ^= reinterpret_cast<uint64_t>(heap_alloc);
                HeapFree(GetProcessHeap(), 0, heap_alloc);
            }
#else
            entropy ^= reinterpret_cast<uint64_t>(&entropy);
            entropy ^= static_cast<uint64_t>(time(nullptr));
#endif

            // knuth multiplicative hash mixing
            entropy ^= std::rotl(entropy, 31);
            entropy *= 0x9e3779b97f4a7c15ULL;
            entropy ^= entropy >> 27;
            entropy *= 0x94d049bb133111ebULL;
            entropy ^= entropy >> 31;

            return entropy;
        }

        // xorshift64*
        inline uint64_t runtime_entropy() {
#if CW_KERNEL_MODE
            // thread_local doesn't work in kernel drivers, use interlocked state
            static volatile LONG64 state = 0;

            LONG64 current = InterlockedCompareExchange64(&state, 0, 0);
            if (current == 0) {
                LONG64 seed = static_cast<LONG64>(runtime_entropy_seed());
                InterlockedCompareExchange64(&state, seed, 0);
                current = InterlockedCompareExchange64(&state, 0, 0);
                if (current == 0) current = seed;
            }

            LONG64 x = current;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            InterlockedExchange64(&state, x);
            return static_cast<uint64_t>(x) * 0x2545F4914F6CDD1DULL;
#else
            thread_local uint64_t state = runtime_entropy_seed();
            uint64_t x = state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            state = x;
            return x * 0x2545F4914F6CDD1DULL;
#endif
        }

#if CW_KERNEL_MODE
        // consteval with __TIME__/__DATE__ doesn't work properly in WDK
        constexpr uint32_t compile_seed_impl(uint32_t line, uint32_t counter) {
            uint32_t seed = 0xDEADBEEF;
            seed ^= line * 0x01000193;
            seed ^= counter * 0x811c9dc5;
            seed *= 0x1664525;
            seed += 0x1013904223;
            return seed;
        }

        #define CW_COMPILE_SEED() (cloakwork::detail::compile_seed_impl(__LINE__, __COUNTER__))

        template<uint32_t Seed>
        struct random_generator {
            static constexpr uint32_t value() {
                return (Seed * 1664525u + 1013904223u);
            }
            static constexpr uint32_t next() {
                return random_generator<value()>::value();
            }
        };
    }

    #define CW_RANDOM_CT() (cloakwork::detail::random_generator<CW_COMPILE_SEED()>::value())
    #define CW_RAND_CT(min, max) ((min) + (CW_RANDOM_CT() % ((max) - (min) + 1)))

#else
        constexpr uint32_t compile_seed() {
            constexpr uint32_t time_hash = fnv1a_hash(__TIME__);
            constexpr uint32_t date_hash = fnv1a_hash(__DATE__);
            constexpr uint32_t file_hash = fnv1a_hash(__FILE__);
            return time_hash ^ (date_hash << 1) ^ (file_hash >> 1) ^ __LINE__;
        }

        template<uint32_t Seed>
        struct random_generator {
            static constexpr uint32_t value() {
                return (Seed * 1664525u + 1013904223u) ^ __COUNTER__;
            }
            static constexpr uint32_t next() {
                return random_generator<value()>::value();
            }
        };
    }

    #define CW_RANDOM_CT() (cloakwork::detail::random_generator<cloakwork::detail::compile_seed() ^ __COUNTER__>::value())
    #define CW_RAND_CT(min, max) ((min) + (CW_RANDOM_CT() % ((max) - (min) + 1)))
#endif

    #define CW_RANDOM_RT() (cloakwork::detail::runtime_entropy())
    #define CW_RAND_RT(min, max) ((min) + (CW_RANDOM_RT() % ((max) - (min) + 1)))

    #define CW_RANDOM() CW_RANDOM_CT()
    #define CW_RAND(min, max) CW_RAND_CT(min, max)
#else
    #define CW_RANDOM_CT() (rand())
    #define CW_RAND_CT(min, max) ((min) + (rand() % ((max) - (min) + 1)))
    #define CW_RANDOM_RT() (rand())
    #define CW_RAND_RT(min, max) ((min) + (rand() % ((max) - (min) + 1)))
    #define CW_RANDOM() (rand())
    #define CW_RAND(min, max) ((min) + (rand() % ((max) - (min) + 1)))
#endif

    namespace hash {
        consteval uint32_t fnv1a(const char* str, size_t len) {
            uint32_t hash = 0x811c9dc5;
            for (size_t i = 0; i < len; ++i) {
                hash ^= static_cast<uint8_t>(str[i]);
                hash *= 0x01000193;
            }
            return hash;
        }

        template<size_t N>
        consteval uint32_t fnv1a(const char (&str)[N]) {
            return fnv1a(str, N - 1);
        }

        consteval uint32_t fnv1a_wide(const wchar_t* str, size_t len) {
            uint32_t hash = 0x811c9dc5;
            for (size_t i = 0; i < len; ++i) {
                hash ^= static_cast<uint8_t>(str[i] & 0xFF);
                hash *= 0x01000193;
                hash ^= static_cast<uint8_t>((str[i] >> 8) & 0xFF);
                hash *= 0x01000193;
            }
            return hash;
        }

        template<size_t N>
        consteval uint32_t fnv1a_wide(const wchar_t (&str)[N]) {
            return fnv1a_wide(str, N - 1);
        }

        CW_FORCEINLINE uint32_t fnv1a_runtime(const char* str) {
            uint32_t hash = 0x811c9dc5;
            while (*str) {
                hash ^= static_cast<uint8_t>(*str++);
                hash *= 0x01000193;
            }
            return hash;
        }

        CW_FORCEINLINE uint32_t fnv1a_runtime(const wchar_t* str) {
            uint32_t hash = 0x811c9dc5;
            while (*str) {
                hash ^= static_cast<uint8_t>(*str & 0xFF);
                hash *= 0x01000193;
                hash ^= static_cast<uint8_t>((*str >> 8) & 0xFF);
                hash *= 0x01000193;
                ++str;
            }
            return hash;
        }

        CW_FORCEINLINE uint32_t fnv1a_runtime_ci(const char* str) {
            uint32_t hash = 0x811c9dc5;
            while (*str) {
                char c = *str++;
                if (c >= 'A' && c <= 'Z') c += 32;
                hash ^= static_cast<uint8_t>(c);
                hash *= 0x01000193;
            }
            return hash;
        }

        CW_FORCEINLINE uint32_t fnv1a_runtime_ci(const wchar_t* str) {
            uint32_t hash = 0x811c9dc5;
            while (*str) {
                wchar_t c = *str++;
                if (c >= L'A' && c <= L'Z') c += 32;
                hash ^= static_cast<uint8_t>(c & 0xFF);
                hash *= 0x01000193;
                hash ^= static_cast<uint8_t>((c >> 8) & 0xFF);
                hash *= 0x01000193;
            }
            return hash;
        }

        // hashes wide string using only the ascii byte, for comparing against CW_HASH_CI
        CW_FORCEINLINE uint32_t fnv1a_runtime_ci_w2a(const wchar_t* str) {
            uint32_t hash = 0x811c9dc5;
            while (*str) {
                wchar_t c = *str++;
                if (c >= L'A' && c <= L'Z') c += 32;
                // only use low byte (ascii portion) to match CW_HASH_CI behavior
                hash ^= static_cast<uint8_t>(c & 0xFF);
                hash *= 0x01000193;
            }
            return hash;
        }

        consteval uint32_t fnv1a_ci(const char* str, size_t len) {
            uint32_t hash = 0x811c9dc5;
            for (size_t i = 0; i < len; ++i) {
                char c = str[i];
                if (c >= 'A' && c <= 'Z') c += 32;
                hash ^= static_cast<uint8_t>(c);
                hash *= 0x01000193;
            }
            return hash;
        }

        template<size_t N>
        consteval uint32_t fnv1a_ci(const char (&str)[N]) {
            return fnv1a_ci(str, N - 1);
        }
    }

    #define CW_HASH(s) ([]() consteval { return cloakwork::hash::fnv1a(s); }())
    #define CW_HASH_WIDE(s) ([]() consteval { return cloakwork::hash::fnv1a_wide(s); }())
    #define CW_HASH_CI(s) ([]() consteval { return cloakwork::hash::fnv1a_ci(s); }())

    namespace internal_cipher {

        // position-dependent xor cipher to prevent Hex-Rays stack-string reconstruction
        template<uint32_t Key, size_t N>
        struct encrypted_buf {
            uint8_t data[N];

            consteval encrypted_buf(const char (&str)[N]) : data{} {
                for (size_t i = 0; i < N; ++i) {
                    uint32_t subkey = Key ^ (static_cast<uint32_t>(i) * 0x9E3779B9u);
                    subkey ^= subkey >> 16;
                    subkey *= 0x45D9F3Bu;
                    subkey ^= subkey >> 13;
                    data[i] = static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(subkey);
                }
            }
        };

        template<uint32_t Key, size_t N>
        CW_NOINLINE void decrypt_to_stack(const encrypted_buf<Key, N>& enc, char (&out)[N]) {
            volatile uint8_t* dst = reinterpret_cast<volatile uint8_t*>(out);
            for (size_t i = 0; i < N; ++i) {
                uint32_t subkey = Key ^ (static_cast<uint32_t>(i) * 0x9E3779B9u);
                subkey ^= subkey >> 16;
                subkey *= 0x45D9F3Bu;
                subkey ^= subkey >> 13;
                dst[i] = enc.data[i] ^ static_cast<uint8_t>(subkey);
            }
            CW_COMPILER_BARRIER();
        }

        template<size_t N>
        CW_FORCEINLINE void zero_buf(char (&buf)[N]) {
            volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(buf);
            for (size_t i = 0; i < N; ++i) p[i] = 0;
            CW_COMPILER_BARRIER();
        }

        // avoids strstr IAT entry
        CW_FORCEINLINE const char* find_substr(const char* haystack, const char* needle) {
            if (!haystack || !needle || !*needle) return haystack;
            for (const char* h = haystack; *h; ++h) {
                const char* h2 = h;
                const char* n = needle;
                while (*h2 && *n && *h2 == *n) { ++h2; ++n; }
                if (!*n) return h;
            }
            return nullptr;
        }
    }

    #define CW_ADSTR(name, str) \
        static constexpr cloakwork::internal_cipher::encrypted_buf< \
            __LINE__ * 0x45D9F3Bu + static_cast<uint32_t>(sizeof(str)) * 0x9E3779B9u, sizeof(str)> \
            _cw_adenc_##name(str); \
        char name[sizeof(str)]; \
        cloakwork::internal_cipher::decrypt_to_stack(_cw_adenc_##name, name)

    #define CW_ADSTR_ZERO(name) \
        cloakwork::internal_cipher::zero_buf(name)

#if CW_ENABLE_ANTI_DEBUG
    namespace anti_debug {

        // self-contained module/proc resolution that avoids IAT entries
        namespace detail {

            CW_FORCEINLINE void* get_module_by_hash(uint32_t module_hash) {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
#ifdef _WIN64
                    auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
                    auto peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
                    if (!peb || !peb->Ldr) return nullptr;

                    auto ldr = peb->Ldr;
                    auto head = &ldr->InMemoryOrderModuleList;
                    for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
                        auto entry = CONTAINING_RECORD(curr, cloakwork_internal::CW_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                        if (!entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) continue;
                        if (hash::fnv1a_runtime_ci_w2a(entry->BaseDllName.Buffer) == module_hash)
                            return entry->DllBase;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return nullptr;
                }
#endif
                return nullptr;
            }

            CW_FORCEINLINE bool is_module_loaded(uint32_t module_hash) {
                return get_module_by_hash(module_hash) != nullptr;
            }

            CW_FORCEINLINE void* get_proc_by_hash(void* module, uint32_t func_hash) {
#if defined(_WIN32) && !CW_KERNEL_MODE
                if (!module) return nullptr;
                __try {
                    auto dos = static_cast<IMAGE_DOS_HEADER*>(module);
                    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
                    if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) return nullptr;

                    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                        reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
                    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

                    uint32_t image_size = nt->OptionalHeader.SizeOfImage;
                    if (image_size == 0 || image_size > 0x7FFFFFFF) return nullptr;

                    auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0) return nullptr;

                    auto base = reinterpret_cast<uint8_t*>(module);
                    auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exp_dir.VirtualAddress);

                    auto names     = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
                    auto ordinals  = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
                    auto functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

                    for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
                        auto name = reinterpret_cast<const char*>(base + names[i]);
                        if (hash::fnv1a_runtime(name) == func_hash) {
                            uint16_t ordinal = ordinals[i];
                            if (ordinal >= exports->NumberOfFunctions) return nullptr;
                            return base + functions[ordinal];
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return nullptr;
                }
#endif
                return nullptr;
            }

            // runtime hash for 12-byte CPUID vendor buffer (not null-terminated, fixed len)
            CW_FORCEINLINE uint32_t hash_vendor_12(const char* buf) {
                uint32_t h = 0x811c9dc5;
                for (int i = 0; i < 12; ++i) {
                    h ^= static_cast<uint8_t>(buf[i]);
                    h *= 0x01000193;
                }
                return h;
            }

            // compile-time hash for 12-byte vendor string literals
            static consteval uint32_t hash_vendor_12_ct(const char* buf, size_t len) {
                uint32_t h = 0x811c9dc5;
                size_t n = len < 12 ? len : 12;
                for (size_t i = 0; i < n; ++i) {
                    h ^= static_cast<uint8_t>(buf[i]);
                    h *= 0x01000193;
                }
                // pad with zeros if shorter than 12
                for (size_t i = n; i < 12; ++i) {
                    h ^= 0;
                    h *= 0x01000193;
                }
                return h;
            }
        }

        inline uint32_t compute_crc32(const uint8_t* data, size_t length) {
            uint32_t crc = 0xFFFFFFFF;
            for (size_t i = 0; i < length; ++i) {
                crc ^= data[i];
                for (int j = 0; j < 8; ++j) {
                    crc = (crc >> 1) ^ (0xEDB88320 & (0 - (crc & 1)));
                }
            }
            return ~crc;
        }

        template<typename Func>
        inline bool verify_code_integrity(Func func, size_t expected_size, uint32_t expected_hash) {
            const uint8_t* code = reinterpret_cast<const uint8_t*>(func);
            uint32_t actual_hash = compute_crc32(code, expected_size);
            return actual_hash == expected_hash;
        }

        CW_FORCEINLINE bool is_debugger_present() {
#if CW_KERNEL_MODE
            if (*KdDebuggerEnabled) return true;
            if (!*KdDebuggerNotPresent) return true;

            // PsIsProcessBeingDebugged checks the DebugPort field internally
            PEPROCESS current_process = PsGetCurrentProcess();
            if (current_process) {
                typedef BOOLEAN (*PsIsProcessBeingDebuggedFn)(PEPROCESS Process);
                static PsIsProcessBeingDebuggedFn PsIsProcessBeingDebugged = nullptr;
                static bool resolved = false;

                if (!resolved) {
                    UNICODE_STRING func_name;
                    RtlInitUnicodeString(&func_name, L"PsIsProcessBeingDebugged");
                    PsIsProcessBeingDebugged = reinterpret_cast<PsIsProcessBeingDebuggedFn>(
                        MmGetSystemRoutineAddress(&func_name));
                    resolved = true;
                }

                if (PsIsProcessBeingDebugged && PsIsProcessBeingDebugged(current_process)) {
                    return true;
                }
            }

            return false;

#elif defined(_WIN32)
            // PEB-only, no IAT import
            __try {
#ifdef _WIN64
                PPEB peb = (PPEB)__readgsqword(0x60);
                if (peb && peb->BeingDebugged) return true;

                DWORD nt_global_flag = *reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(peb) + 0xBC);
                if (nt_global_flag & 0x70) return true; // 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMS
#else
                PPEB peb = (PPEB)__readfsdword(0x30);
                if (peb && peb->BeingDebugged) return true;

                DWORD nt_global_flag = *reinterpret_cast<DWORD*>(reinterpret_cast<uint8_t*>(peb) + 0x68);
                if (nt_global_flag & 0x70) return true;
#endif
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
            }
            return false;
#else
            return false;
#endif
        }

        template<typename Func>
        CW_FORCEINLINE bool timing_check(Func func, uint64_t threshold = 10000) {
#if CW_KERNEL_MODE
            LARGE_INTEGER freq;
            LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);

            uint64_t tsc_start = __rdtsc();

            func();

            LARGE_INTEGER end = KeQueryPerformanceCounter(nullptr);
            uint64_t tsc_end = __rdtsc();

            if (freq.QuadPart == 0) return false;

            uint64_t qpc_elapsed = ((end.QuadPart - start.QuadPart) * 1000000) / freq.QuadPart;
            uint64_t tsc_elapsed = tsc_end - tsc_start;

            // check if either clock shows suspicious delay
            if (qpc_elapsed > threshold || tsc_elapsed > threshold * 100) {
                return true;
            }

            // check for clock desync (kernel debugger stepping)
            if (qpc_elapsed > 0 && tsc_elapsed > 0) {
                double ratio = static_cast<double>(tsc_elapsed) / static_cast<double>(qpc_elapsed);
                if (ratio < 0.5 || ratio > 100000.0) return true;
            }

            return false;

#elif defined(_WIN32)
            LARGE_INTEGER start, end, freq;
            QueryPerformanceFrequency(&freq);

            uint64_t tsc_start = __rdtsc();
            QueryPerformanceCounter(&start);

            func();

            QueryPerformanceCounter(&end);
            uint64_t tsc_end = __rdtsc();

            uint64_t qpc_elapsed = ((end.QuadPart - start.QuadPart) * 1000000) / freq.QuadPart;
            uint64_t tsc_elapsed = tsc_end - tsc_start;

            // check if either clock shows suspicious delay
            if (qpc_elapsed > threshold || tsc_elapsed > threshold * 100) {
                return true;
            }

            // check for clock desync (one is hooked)
            if (qpc_elapsed > 0 && tsc_elapsed > 0) {
                double ratio = static_cast<double>(tsc_elapsed) / static_cast<double>(qpc_elapsed);
                if (ratio < 0.5 || ratio > 100000.0) return true;
            }

            return false;
#else
            return false;
#endif
        }

        CW_FORCEINLINE bool has_breakpoints(void* addr, size_t size) {
            uint8_t* bytes = reinterpret_cast<uint8_t*>(addr);
            for(size_t i = 0; i < size; ++i) {
                if(bytes[i] == 0xCC) return true; // int3 instruction
            }
            return false;
        }

        CW_FORCEINLINE bool has_hardware_breakpoints() {
#if CW_KERNEL_MODE
            // DR0-DR3: non-zero means hardware breakpoints are set
#ifdef _WIN64
            uint64_t dr0 = __readdr(0);
            uint64_t dr1 = __readdr(1);
            uint64_t dr2 = __readdr(2);
            uint64_t dr3 = __readdr(3);
            return (dr0 || dr1 || dr2 || dr3);
#else
            // x86 uses inline asm (not available in MSVC x64)
            unsigned long dr0, dr1, dr2, dr3;
            __asm {
                mov eax, dr0
                mov dr0, eax
                mov eax, dr1
                mov dr1, eax
                mov eax, dr2
                mov dr2, eax
                mov eax, dr3
                mov dr3, eax
            }
            return (dr0 || dr1 || dr2 || dr3);
#endif

#elif defined(_WIN32)
            // dynamically resolve GetThreadContext to avoid IAT entry
            {
                auto kernel32 = detail::get_module_by_hash(CW_HASH_CI("kernel32.dll"));
                if (!kernel32) return false;

                auto pGetThreadContext = reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPCONTEXT)>(
                    detail::get_proc_by_hash(kernel32, CW_HASH("GetThreadContext")));
                if (!pGetThreadContext) return false;

                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (pGetThreadContext(GetCurrentThread(), &ctx)) {
                    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
                }
            }
            return false;
#else
            return false;
#endif
        }

        namespace advanced {

            CW_FORCEINLINE bool detect_hiding_tools() {
#if CW_KERNEL_MODE
                return false;
#elif defined(_WIN32)
                __try {
                    constexpr uint32_t hiding_dll_hashes[] = {
                        CW_HASH_CI("scylla_hide.dll"),
                        CW_HASH_CI("ScyllaHideX64.dll"),
                        CW_HASH_CI("ScyllaHideX86.dll"),
                        CW_HASH_CI("TitanHide.dll"),
                        CW_HASH_CI("HyperHide.dll"),
                    };

                    for (auto h : hiding_dll_hashes) {
                        if (detail::is_module_loaded(h)) return true;
                    }

                    auto user32 = detail::get_module_by_hash(CW_HASH_CI("user32.dll"));
                    if (!user32) return false;

                    auto pEnumWindows = reinterpret_cast<BOOL(WINAPI*)(WNDENUMPROC, LPARAM)>(
                        detail::get_proc_by_hash(user32, CW_HASH("EnumWindows")));
                    auto pGetClassNameA = reinterpret_cast<int(WINAPI*)(HWND, LPSTR, int)>(
                        detail::get_proc_by_hash(user32, CW_HASH("GetClassNameA")));
                    auto pGetWindowTextA = reinterpret_cast<int(WINAPI*)(HWND, LPSTR, int)>(
                        detail::get_proc_by_hash(user32, CW_HASH("GetWindowTextA")));

                    if (pEnumWindows && pGetClassNameA && pGetWindowTextA) {
                        constexpr uint32_t dbg_class_hashes[] = {
                            CW_HASH("OLLYDBG"),
                            CW_HASH("WinDbgFrameClass"),
                            CW_HASH("ID"),
                            CW_HASH("ObsidianGUI"),
                        };
                        constexpr uint32_t dbg_title_hashes[] = {
                            CW_HASH("x64dbg"),
                            CW_HASH("x32dbg"),
                            CW_HASH("x96dbg"),
                            CW_HASH("Zeta Debugger"),
                            CW_HASH("Rock Debugger"),
                        };

                        struct enum_ctx {
                            bool found;
                            const uint32_t* class_hashes;
                            size_t class_count;
                            const uint32_t* title_hashes;
                            size_t title_count;
                            decltype(pGetClassNameA) getClassName;
                            decltype(pGetWindowTextA) getWindowText;
                        };

                        enum_ctx ctx = {
                            false, dbg_class_hashes, sizeof(dbg_class_hashes)/sizeof(uint32_t),
                            dbg_title_hashes, sizeof(dbg_title_hashes)/sizeof(uint32_t),
                            pGetClassNameA, pGetWindowTextA
                        };

                        pEnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                            auto* c = reinterpret_cast<enum_ctx*>(lParam);
                            char buf[256];
                            if (c->getClassName(hwnd, buf, sizeof(buf))) {
                                uint32_t h = hash::fnv1a_runtime(buf);
                                for (size_t i = 0; i < c->class_count; ++i)
                                    if (h == c->class_hashes[i]) { c->found = true; return FALSE; }
                            }
                            if (c->getWindowText(hwnd, buf, sizeof(buf)) > 0) {
                                uint32_t h = hash::fnv1a_runtime(buf);
                                for (size_t i = 0; i < c->title_count; ++i)
                                    if (h == c->title_hashes[i]) { c->found = true; return FALSE; }
                            }
                            return TRUE;
                        }, reinterpret_cast<LPARAM>(&ctx));

                        if (ctx.found) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool kernel_debugger_present() {
#if CW_KERNEL_MODE
                if (*KdDebuggerEnabled) return true;
                if (!*KdDebuggerNotPresent) return true;

                // check SystemKernelDebuggerInformation via ZwQuerySystemInformation
                struct {
                    BOOLEAN KernelDebuggerEnabled;
                    BOOLEAN KernelDebuggerNotPresent;
                } kernel_debug_info = {};

                ULONG return_length = 0;
                // SYSTEM_INFORMATION_CLASS is not always defined, use raw value
                NTSTATUS status = ZwQuerySystemInformation(
                    23,  // SystemKernelDebuggerInformation
                    &kernel_debug_info,
                    sizeof(kernel_debug_info),
                    &return_length);

                if (NT_SUCCESS(status)) {
                    if (kernel_debug_info.KernelDebuggerEnabled ||
                        !kernel_debug_info.KernelDebuggerNotPresent) {
                        return true;
                    }
                }

                return false;

#elif defined(_WIN32)
                __try {
                    typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
                        ULONG SystemInformationClass,
                        PVOID SystemInformation,
                        ULONG SystemInformationLength,
                        PULONG ReturnLength
                    );

                    auto ntdll = detail::get_module_by_hash(CW_HASH_CI("ntdll.dll"));
                    if (!ntdll) return false;

                    auto NtQuerySystemInformation =
                        reinterpret_cast<pNtQuerySystemInformation>(
                            detail::get_proc_by_hash(ntdll, CW_HASH("NtQuerySystemInformation")));

                    if (NtQuerySystemInformation) {
                        ULONG kernel_debug = 0;
                        // SystemKernelDebuggerInformation = 0x23
                        NTSTATUS status = NtQuerySystemInformation(0x23, &kernel_debug, sizeof(kernel_debug), nullptr);
                        if (status == 0 && kernel_debug != 0) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool suspicious_parent_process() {
#if CW_KERNEL_MODE
                PEPROCESS current = PsGetCurrentProcess();
                if (!current) return false;

                // parent pid offset varies by windows version, skip in kernel
                return false;

#elif defined(_WIN32)
                __try {
                    auto kernel32 = detail::get_module_by_hash(CW_HASH_CI("kernel32.dll"));
                    if (!kernel32) return false;

                    auto pCreateToolhelp32Snapshot = reinterpret_cast<HANDLE(WINAPI*)(DWORD, DWORD)>(
                        detail::get_proc_by_hash(kernel32, CW_HASH("CreateToolhelp32Snapshot")));
                    auto pProcess32FirstW = reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W)>(
                        detail::get_proc_by_hash(kernel32, CW_HASH("Process32FirstW")));
                    auto pProcess32NextW = reinterpret_cast<BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W)>(
                        detail::get_proc_by_hash(kernel32, CW_HASH("Process32NextW")));

                    if (!pCreateToolhelp32Snapshot || !pProcess32FirstW || !pProcess32NextW)
                        return false;

                    HANDLE snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (snapshot == INVALID_HANDLE_VALUE) return false;

                    PROCESSENTRY32W pe;
                    pe.dwSize = sizeof(PROCESSENTRY32W);
                    DWORD current_pid = GetCurrentProcessId();
                    DWORD parent_pid = 0;

                    if (pProcess32FirstW(snapshot, &pe)) {
                        do {
                            if (pe.th32ProcessID == current_pid) {
                                parent_pid = pe.th32ParentProcessID;
                                break;
                            }
                        } while (pProcess32NextW(snapshot, &pe));
                    }

                    // find parent process name and compare via hash (no plaintext exe names)
                    if (parent_pid) {
                        constexpr uint32_t suspicious_parent_hashes[] = {
                            CW_HASH_CI("x64dbg.exe"),
                            CW_HASH_CI("x32dbg.exe"),
                            CW_HASH_CI("ollydbg.exe"),
                            CW_HASH_CI("ida.exe"),
                            CW_HASH_CI("ida64.exe"),
                            CW_HASH_CI("windbg.exe"),
                            CW_HASH_CI("immunitydebugger.exe"),
                            CW_HASH_CI("cheatengine-x86_64.exe"),
                            CW_HASH_CI("cheatengine-i386.exe"),
                            CW_HASH_CI("processhacker.exe"),
                        };

                        pe.dwSize = sizeof(PROCESSENTRY32W);
                        if (pProcess32FirstW(snapshot, &pe)) {
                            do {
                                if (pe.th32ProcessID == parent_pid) {
                                    uint32_t name_hash = hash::fnv1a_runtime_ci_w2a(pe.szExeFile);
                                    for (auto h : suspicious_parent_hashes) {
                                        if (name_hash == h) {
                                            CloseHandle(snapshot);
                                            return true;
                                        }
                                    }
                                    break;
                                }
                            } while (pProcess32NextW(snapshot, &pe));
                        }
                    }

                    CloseHandle(snapshot);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_memory_breakpoints(void* address, size_t size) {
#if CW_KERNEL_MODE
                if (!MmIsAddressValid(address)) return false;
                return false;

#elif defined(_WIN32)
                MEMORY_BASIC_INFORMATION mbi;
                uint8_t* ptr = static_cast<uint8_t*>(address);
                size_t remaining = size;

                while (remaining > 0) {
                    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) break;

                    // check for page guard (used for memory breakpoints)
                    if (mbi.Protect & PAGE_GUARD) return true;

                    size_t block_size = mbi.RegionSize - (ptr - static_cast<uint8_t*>(mbi.BaseAddress));
                    if (block_size > remaining) block_size = remaining;

                    ptr += block_size;
                    remaining -= block_size;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_debugger_artifacts() {
#if CW_KERNEL_MODE
                return false;

#elif defined(_WIN32)
                __try {
                    auto advapi32 = detail::get_module_by_hash(CW_HASH_CI("advapi32.dll"));
                    if (!advapi32) return false;

                    auto pRegOpenKeyExA = reinterpret_cast<LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY)>(
                        detail::get_proc_by_hash(advapi32, CW_HASH("RegOpenKeyExA")));
                    auto pRegCloseKey = reinterpret_cast<LSTATUS(WINAPI*)(HKEY)>(
                        detail::get_proc_by_hash(advapi32, CW_HASH("RegCloseKey")));
                    if (!pRegOpenKeyExA || !pRegCloseKey) return false;

                    HKEY key;

                    // helper lambda to probe registry in both HKCU and HKLM
                    auto check_key = [&](const char* path) -> bool {
                        if (pRegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
                            pRegCloseKey(key);
                            return true;
                        }
                        if (pRegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
                            pRegCloseKey(key);
                            return true;
                        }
                        return false;
                    };

                    // compile-time encrypted registry key strings (not reconstructable by Hex-Rays)
                    { CW_ADSTR(k0, "SOFTWARE\\x64dbg");
                      if (check_key(k0)) { CW_ADSTR_ZERO(k0); return true; }
                      CW_ADSTR_ZERO(k0); }

                    { CW_ADSTR(k1, "SOFTWARE\\OllyDbg");
                      if (check_key(k1)) { CW_ADSTR_ZERO(k1); return true; }
                      CW_ADSTR_ZERO(k1); }

                    { CW_ADSTR(k2, "SOFTWARE\\Immunity Inc\\Immunity Debugger");
                      if (check_key(k2)) { CW_ADSTR_ZERO(k2); return true; }
                      CW_ADSTR_ZERO(k2); }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool advanced_timing_check() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    LARGE_INTEGER freq, qpc_start, qpc_end;
                    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
                        return false;
                    }

                    uint64_t tsc_start = __rdtsc();
                    QueryPerformanceCounter(&qpc_start);

                    volatile int dummy = 0;
                    for (int i = 0; i < 100; i++) {
                        dummy += i;
                        CW_COMPILER_BARRIER();
                    }

                    QueryPerformanceCounter(&qpc_end);
                    uint64_t tsc_end = __rdtsc();

                    uint64_t tsc_delta = tsc_end - tsc_start;
                    uint64_t qpc_delta_us = ((qpc_end.QuadPart - qpc_start.QuadPart) * 1000000) / freq.QuadPart;

                    // threshold derived from compile-time random
                    constexpr uint64_t tsc_thresh = 800000 + (CW_RANDOM_CT() % 400000);
                    if (tsc_delta > tsc_thresh) return true;

                    // check for inconsistent timing (one clock source is hooked)
                    if (qpc_delta_us > 0) {
                        double ratio = static_cast<double>(tsc_delta) / static_cast<double>(qpc_delta_us);
                        if (ratio < 0.5 || ratio > 100000.0) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }
        }

        CW_FORCEINLINE bool comprehensive_check() {
            __try {
                if (is_debugger_present()) return true;
                if (has_hardware_breakpoints()) return true;

                // threshold derived from compile-time random to prevent easy constant patching
                constexpr uint64_t timing_threshold = 40000 + (CW_RANDOM_CT() % 20000);
                bool timing_suspicious = timing_check([]() {
                    volatile int dummy = 0;
                    for (int i = 0; i < 100; i++) {
                        dummy += i;
                        CW_COMPILER_BARRIER();
                    }
                }, timing_threshold);

                if (timing_suspicious) return true;

                __try {
                    if (advanced::detect_hiding_tools()) return true;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                __try {
                    if (advanced::kernel_debugger_present()) return true;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                __try {
                    if (advanced::suspicious_parent_process()) return true;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}

                return false;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        CW_FORCEINLINE void inline_check() {
#if CW_ANTI_DEBUG_RESPONSE == 1
            if (is_debugger_present() || has_hardware_breakpoints()) {
                __debugbreak();
                *(volatile int*)0 = 0;
            }
#elif CW_ANTI_DEBUG_RESPONSE == 2
            // fake response - pretend to work but return garbage
            // implementation depends on context
#endif
        }

#if CW_ENABLE_ANTI_VM
        namespace anti_vm {

            CW_FORCEINLINE bool is_hypervisor_present() {
#if defined(_WIN32)
                int cpuInfo[4];
                __cpuid(cpuInfo, 1);
                return (cpuInfo[2] >> 31) & 1;  // hypervisor bit
#else
                return false;
#endif
            }

            CW_FORCEINLINE bool detect_vm_vendor() {
#if defined(_WIN32)
                __try {
                    int cpuInfo[4];
                    __cpuid(cpuInfo, 0x40000000);

                    char vendor[13];
                    memcpy(vendor, &cpuInfo[1], 4);
                    memcpy(vendor + 4, &cpuInfo[2], 4);
                    memcpy(vendor + 8, &cpuInfo[3], 4);
                    vendor[12] = 0;

                    // compare vendor string via hash (no plaintext vendor strings in binary)
                    uint32_t vendor_hash = detail::hash_vendor_12(vendor);

                    constexpr uint32_t vm_vendor_hashes[] = {
                        detail::hash_vendor_12_ct("VMwareVMware", 12),
                        detail::hash_vendor_12_ct("Microsoft Hv", 12),
                        detail::hash_vendor_12_ct("VBoxVBoxVBox", 12),
                        detail::hash_vendor_12_ct("KVMKVMKVM\0\0\0", 12),
                        detail::hash_vendor_12_ct("XenVMMXenVMM", 12),
                        detail::hash_vendor_12_ct("prl hyperv  ", 12),
                        detail::hash_vendor_12_ct("TCGTCGTCGTCG", 12),
                    };

                    for (auto h : vm_vendor_hashes) {
                        if (vendor_hash == h) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_low_resources() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    SYSTEM_INFO si;
                    GetSystemInfo(&si);
                    if (si.dwNumberOfProcessors < 2) return true;

                    MEMORYSTATUSEX ms{sizeof(ms)};
                    GlobalMemoryStatusEx(&ms);
                    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;

                    ULARGE_INTEGER freeBytesAvailable, totalBytes, freeBytes;
                    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &freeBytes)) {
                        if (totalBytes.QuadPart < 60ULL * 1024 * 1024 * 1024) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_sandbox_dlls() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    constexpr uint32_t sandbox_dll_hashes[] = {
                        CW_HASH_CI("SbieDll.dll"),       // sandboxie
                        CW_HASH_CI("dbghelp.dll"),       // often loaded by analysis tools
                        CW_HASH_CI("api_log.dll"),       // api logging
                        CW_HASH_CI("dir_watch.dll"),     // directory watching
                        CW_HASH_CI("pstorec.dll"),       // password store
                        CW_HASH_CI("vmcheck.dll"),       // vm check library
                        CW_HASH_CI("wpespy.dll"),        // wpe pro
                        CW_HASH_CI("cmdvrt32.dll"),      // comodo sandbox
                        CW_HASH_CI("cmdvrt64.dll"),      // comodo sandbox
                        CW_HASH_CI("cuckoomon.dll"),     // cuckoo sandbox
                    };

                    for (auto h : sandbox_dll_hashes) {
                        if (detail::is_module_loaded(h)) return true;
                    }

                    auto user32 = detail::get_module_by_hash(CW_HASH_CI("user32.dll"));
                    if (user32) {
                        auto pEnumWindows = reinterpret_cast<BOOL(WINAPI*)(WNDENUMPROC, LPARAM)>(
                            detail::get_proc_by_hash(user32, CW_HASH("EnumWindows")));
                        auto pGetClassNameA = reinterpret_cast<int(WINAPI*)(HWND, LPSTR, int)>(
                            detail::get_proc_by_hash(user32, CW_HASH("GetClassNameA")));

                        if (pEnumWindows && pGetClassNameA) {
                            constexpr uint32_t tool_class_hashes[] = {
                                CW_HASH("PROCMON_WINDOW_CLASS"),
                                CW_HASH("FilemonClass"),
                                CW_HASH("RegmonClass"),
                                CW_HASH("Autoruns"),
                            };

                            struct sb_enum_ctx {
                                bool found;
                                const uint32_t* hashes;
                                size_t count;
                                decltype(pGetClassNameA) getClassName;
                            };

                            sb_enum_ctx ctx = { false, tool_class_hashes,
                                sizeof(tool_class_hashes)/sizeof(uint32_t), pGetClassNameA };

                            pEnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                                auto* c = reinterpret_cast<sb_enum_ctx*>(lParam);
                                char buf[256];
                                if (c->getClassName(hwnd, buf, sizeof(buf))) {
                                    uint32_t h = hash::fnv1a_runtime(buf);
                                    for (size_t i = 0; i < c->count; ++i)
                                        if (h == c->hashes[i]) { c->found = true; return FALSE; }
                                }
                                return TRUE;
                            }, reinterpret_cast<LPARAM>(&ctx));

                            if (ctx.found) return true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            // compile-time encrypted search strings + inline substr (no strstr in IAT)
            CW_FORCEINLINE bool detect_sandbox_names() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    char buffer[256];
                    DWORD size = sizeof(buffer);

                    if (GetUserNameA(buffer, &size)) {
                        for (DWORD i = 0; i < size && buffer[i]; ++i)
                            if (buffer[i] >= 'A' && buffer[i] <= 'Z') buffer[i] += 32;

                        CW_ADSTR(s0, "sandbox"); CW_ADSTR(s1, "virus");
                        CW_ADSTR(s2, "malware"); CW_ADSTR(s3, "sample");
                        CW_ADSTR(s4, "test");    CW_ADSTR(s5, "user");
                        CW_ADSTR(s6, "admin");   CW_ADSTR(s7, "currentuser");
                        CW_ADSTR(s8, "vmware");  CW_ADSTR(s9, "vbox");

                        const char* checks[] = { s0, s1, s2, s3, s4, s5, s6, s7, s8, s9 };
                        for (auto c : checks) {
                            if (internal_cipher::find_substr(buffer, c)) {
                                CW_ADSTR_ZERO(s0); CW_ADSTR_ZERO(s1); CW_ADSTR_ZERO(s2);
                                CW_ADSTR_ZERO(s3); CW_ADSTR_ZERO(s4); CW_ADSTR_ZERO(s5);
                                CW_ADSTR_ZERO(s6); CW_ADSTR_ZERO(s7); CW_ADSTR_ZERO(s8);
                                CW_ADSTR_ZERO(s9);
                                return true;
                            }
                        }
                        CW_ADSTR_ZERO(s0); CW_ADSTR_ZERO(s1); CW_ADSTR_ZERO(s2);
                        CW_ADSTR_ZERO(s3); CW_ADSTR_ZERO(s4); CW_ADSTR_ZERO(s5);
                        CW_ADSTR_ZERO(s6); CW_ADSTR_ZERO(s7); CW_ADSTR_ZERO(s8);
                        CW_ADSTR_ZERO(s9);
                    }

                    size = sizeof(buffer);
                    if (GetComputerNameA(buffer, &size)) {
                        for (DWORD i = 0; i < size && buffer[i]; ++i)
                            if (buffer[i] >= 'A' && buffer[i] <= 'Z') buffer[i] += 32;

                        CW_ADSTR(c0, "sandbox"); CW_ADSTR(c1, "test");
                        CW_ADSTR(c2, "virus");   CW_ADSTR(c3, "malware");
                        CW_ADSTR(c4, "sample");

                        const char* checks[] = { c0, c1, c2, c3, c4 };
                        for (auto c : checks) {
                            if (internal_cipher::find_substr(buffer, c)) {
                                CW_ADSTR_ZERO(c0); CW_ADSTR_ZERO(c1); CW_ADSTR_ZERO(c2);
                                CW_ADSTR_ZERO(c3); CW_ADSTR_ZERO(c4);
                                return true;
                            }
                        }
                        CW_ADSTR_ZERO(c0); CW_ADSTR_ZERO(c1); CW_ADSTR_ZERO(c2);
                        CW_ADSTR_ZERO(c3); CW_ADSTR_ZERO(c4);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_vm_registry() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    auto advapi32 = detail::get_module_by_hash(CW_HASH_CI("advapi32.dll"));
                    if (!advapi32) return false;

                    auto pRegOpenKeyExA = reinterpret_cast<LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY)>(
                        detail::get_proc_by_hash(advapi32, CW_HASH("RegOpenKeyExA")));
                    auto pRegCloseKey = reinterpret_cast<LSTATUS(WINAPI*)(HKEY)>(
                        detail::get_proc_by_hash(advapi32, CW_HASH("RegCloseKey")));
                    if (!pRegOpenKeyExA || !pRegCloseKey) return false;

                    HKEY key;

                    auto check_hklm = [&](const char* path) -> bool {
                        if (pRegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key) == ERROR_SUCCESS) {
                            pRegCloseKey(key);
                            return true;
                        }
                        return false;
                    };

                    // compile-time encrypted VM registry key strings
                    { CW_ADSTR(k0, "SOFTWARE\\VMware, Inc.\\VMware Tools");
                      if (check_hklm(k0)) { CW_ADSTR_ZERO(k0); return true; }
                      CW_ADSTR_ZERO(k0); }

                    { CW_ADSTR(k1, "SOFTWARE\\Oracle\\VirtualBox Guest Additions");
                      if (check_hklm(k1)) { CW_ADSTR_ZERO(k1); return true; }
                      CW_ADSTR_ZERO(k1); }

                    { CW_ADSTR(k2, "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest");
                      if (check_hklm(k2)) { CW_ADSTR_ZERO(k2); return true; }
                      CW_ADSTR_ZERO(k2); }

                    { CW_ADSTR(k3, "SYSTEM\\CurrentControlSet\\Services\\vmci");
                      if (check_hklm(k3)) { CW_ADSTR_ZERO(k3); return true; }
                      CW_ADSTR_ZERO(k3); }

                    { CW_ADSTR(k4, "SYSTEM\\CurrentControlSet\\Services\\vmhgfs");
                      if (check_hklm(k4)) { CW_ADSTR_ZERO(k4); return true; }
                      CW_ADSTR_ZERO(k4); }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool detect_vm_mac() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                __try {
                    // common VM MAC prefixes (first 3 bytes)
                    const uint8_t vmMacPrefixes[][3] = {
                        {0x00, 0x0C, 0x29},  // vmware
                        {0x00, 0x50, 0x56},  // vmware
                        {0x08, 0x00, 0x27},  // virtualbox
                        {0x00, 0x1C, 0x42},  // parallels
                        {0x00, 0x03, 0xFF},  // hyper-v
                        {0x00, 0x15, 0x5D},  // hyper-v
                    };

                    // get adapter info - use raw allocation to avoid SEH/RAII conflict
                    ULONG bufferSize = 0;
                    GetAdaptersInfo(nullptr, &bufferSize);
                    if (bufferSize == 0) return false;

                    uint8_t* adapters = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), 0, bufferSize));
                    if (!adapters) return false;

                    auto adapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(adapters);
                    bool found = false;

                    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
                        for (auto adapter = adapterInfo; adapter && !found; adapter = adapter->Next) {
                            if (adapter->AddressLength >= 3) {
                                for (int i = 0; i < 6 && !found; ++i) {
                                    if (memcmp(adapter->Address, vmMacPrefixes[i], 3) == 0) {
                                        found = true;
                                    }
                                }
                            }
                        }
                    }

                    HeapFree(GetProcessHeap(), 0, adapters);
                    return found;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
#endif
                return false;
            }

            CW_FORCEINLINE bool comprehensive_check() {
                __try {
                    if (is_hypervisor_present()) return true;
                    if (detect_vm_vendor()) return true;
                    if (detect_low_resources()) return true;
                    if (detect_sandbox_dlls()) return true;
                    if (detect_sandbox_names()) return true;
                    if (detect_vm_registry()) return true;
                    if (detect_vm_mac()) return true;
                    return false;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            }
        } // namespace anti_vm
#endif // CW_ENABLE_ANTI_VM
    }

    #define CW_ANTI_DEBUG() \
        do { \
            if(cloakwork::anti_debug::comprehensive_check()) { \
                __debugbreak(); \
                *(volatile int*)0 = 0; \
            } \
        } while(0)

    #define CW_INLINE_CHECK() cloakwork::anti_debug::inline_check()

    #if CW_ENABLE_ANTI_VM
        #define CW_ANTI_VM() \
            do { \
                if(cloakwork::anti_debug::anti_vm::comprehensive_check()) { \
                    __debugbreak(); \
                    *(volatile int*)0 = 0; \
                } \
            } while(0)

        #define CW_CHECK_VM() (cloakwork::anti_debug::anti_vm::comprehensive_check())
    #else
        #define CW_ANTI_VM() ((void)0)
        #define CW_CHECK_VM() (false)
    #endif

#else
    namespace anti_debug {
        inline bool is_debugger_present() { return false; }
        template<typename Func> inline bool timing_check(Func, uint64_t = 1000) { return false; }
        inline bool has_breakpoints(void*, size_t) { return false; }
        inline bool has_hardware_breakpoints() { return false; }
        inline bool comprehensive_check() { return false; }
        inline void inline_check() {}
        template<typename Func> inline bool verify_code_integrity(Func, size_t, uint32_t) { return true; }

        namespace anti_vm {
            inline bool is_hypervisor_present() { return false; }
            inline bool detect_vm_vendor() { return false; }
            inline bool detect_low_resources() { return false; }
            inline bool detect_sandbox_dlls() { return false; }
            inline bool detect_sandbox_names() { return false; }
            inline bool detect_vm_registry() { return false; }
            inline bool detect_vm_mac() { return false; }
            inline bool comprehensive_check() { return false; }
        }
    }
    #define CW_ANTI_DEBUG() ((void)0)
    #define CW_INLINE_CHECK() ((void)0)
    #define CW_ANTI_VM() ((void)0)
    #define CW_CHECK_VM() (false)
#endif

#if CW_ENABLE_STRING_ENCRYPTION
    namespace string_encrypt {

        // xtea block cipher - 64-bit blocks, 128-bit key, 32 rounds
        // tiny code footprint, fully constexpr, strong against pattern matching
        namespace xtea {
            static constexpr uint32_t DELTA = 0x9E3779B9;
            static constexpr uint32_t ROUNDS = 32;

            struct key128 {
                uint32_t k[4];
            };

            static constexpr void encrypt_block(uint32_t& v0, uint32_t& v1, const key128& key) {
                uint32_t sum = 0;
                for (uint32_t i = 0; i < ROUNDS; ++i) {
                    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key.k[sum & 3]);
                    sum += DELTA;
                    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key.k[(sum >> 11) & 3]);
                }
            }

            static constexpr void decrypt_block(uint32_t& v0, uint32_t& v1, const key128& key) {
                uint32_t sum = DELTA * ROUNDS;
                for (uint32_t i = 0; i < ROUNDS; ++i) {
                    v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key.k[(sum >> 11) & 3]);
                    sum -= DELTA;
                    v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key.k[sum & 3]);
                }
            }

            // templated to avoid reinterpret_cast, which is forbidden in constexpr
            template<typename ByteT>
            static constexpr void encrypt_buffer(ByteT* data, size_t len, const key128& key) {
                for (size_t i = 0; i + 7 < len; i += 8) {
                    uint32_t v0 = static_cast<uint32_t>(static_cast<uint8_t>(data[i]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+1])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+2])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+3])) << 24);
                    uint32_t v1 = static_cast<uint32_t>(static_cast<uint8_t>(data[i+4]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+5])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+6])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+7])) << 24);

                    encrypt_block(v0, v1, key);

                    data[i]   = static_cast<ByteT>(static_cast<uint8_t>(v0));
                    data[i+1] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 8));
                    data[i+2] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 16));
                    data[i+3] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 24));
                    data[i+4] = static_cast<ByteT>(static_cast<uint8_t>(v1));
                    data[i+5] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 8));
                    data[i+6] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 16));
                    data[i+7] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 24));
                }

                // remaining bytes: xor with key material
                size_t tail_start = (len / 8) * 8;
                for (size_t i = tail_start; i < len; ++i) {
                    data[i] = static_cast<ByteT>(static_cast<uint8_t>(data[i]) ^
                        static_cast<uint8_t>(key.k[i % 4] >> ((i % 4) * 8)));
                }
            }

            template<typename ByteT>
            static constexpr void decrypt_buffer(ByteT* data, size_t len, const key128& key) {
                // remaining bytes first (reverse order of encrypt)
                size_t tail_start = (len / 8) * 8;
                for (size_t i = tail_start; i < len; ++i) {
                    data[i] = static_cast<ByteT>(static_cast<uint8_t>(data[i]) ^
                        static_cast<uint8_t>(key.k[i % 4] >> ((i % 4) * 8)));
                }

                for (size_t i = 0; i + 7 < len; i += 8) {
                    uint32_t v0 = static_cast<uint32_t>(static_cast<uint8_t>(data[i]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+1])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+2])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+3])) << 24);
                    uint32_t v1 = static_cast<uint32_t>(static_cast<uint8_t>(data[i+4]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+5])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+6])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+7])) << 24);

                    decrypt_block(v0, v1, key);

                    data[i]   = static_cast<ByteT>(static_cast<uint8_t>(v0));
                    data[i+1] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 8));
                    data[i+2] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 16));
                    data[i+3] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 24));
                    data[i+4] = static_cast<ByteT>(static_cast<uint8_t>(v1));
                    data[i+5] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 8));
                    data[i+6] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 16));
                    data[i+7] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 24));
                }
            }
        }

        template<size_t N,
                 uint32_t K0 = CW_RANDOM_CT(), uint32_t K1 = CW_RANDOM_CT(),
                 uint32_t K2 = CW_RANDOM_CT(), uint32_t K3 = CW_RANDOM_CT()>
        class encrypted_string {
        private:
            std::array<char, N> data;
            mutable CW_ATOMIC(bool) decrypted{false};
            mutable CW_MUTEX mutex;

            static constexpr xtea::key128 compile_key = {{K0, K1, K2, K3}};

            // no reinterpret_cast - uses templated buffer functions for constexpr compatibility
            static constexpr std::array<char, N> encrypt_string(const char* str) {
                std::array<char, N> result{};
                for (size_t i = 0; i < N; ++i) result[i] = str[i];
                xtea::encrypt_buffer(result.data(), N, compile_key);
                return result;
            }

        public:
            template<size_t... I>
            constexpr encrypted_string(const char (&str)[N], std::index_sequence<I...>)
                : data(encrypt_string(str)), decrypted(false) {}

            constexpr encrypted_string(const char (&str)[N])
                : encrypted_string(str, std::make_index_sequence<N>{}) {}

            // noinline + optimization off: prevents LTCG from constant-folding the decrypt
            CW_NOINLINE const char* get() const {
                CW_COMPILER_BARRIER();
                if (!decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (!decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<char, N>&>(data);
                        xtea::decrypt_buffer(mutable_data.data(), N, compile_key);
                        decrypted.store(true, CW_MO_RELAXED);
                    }
                }
                CW_COMPILER_BARRIER();
                return data.data();
            }

            CW_NOINLINE operator const char*() const { return get(); }

            ~encrypted_string() {
                if (decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<char, N>&>(data);
                        xtea::encrypt_buffer(mutable_data.data(), N, compile_key);
                        decrypted.store(false, CW_MO_RELAXED);
                    }
                }
            }
        };

        template<size_t N>
        encrypted_string(const char (&)[N]) -> encrypted_string<N>;

        template<size_t N,
                 uint32_t K0 = CW_RANDOM_CT(), uint32_t K1 = CW_RANDOM_CT(),
                 uint32_t K2 = CW_RANDOM_CT(), uint32_t K3 = CW_RANDOM_CT()>
        class layered_encrypted_string {
        private:
            std::array<char, N> data;
            mutable CW_ATOMIC(bool) decrypted{false};
            mutable CW_ATOMIC(uint32_t) access_count{0};
            mutable CW_MUTEX mutex;
            mutable xtea::key128 current_key;

            static constexpr xtea::key128 compile_key = {{K0, K1, K2, K3}};

            static constexpr std::array<char, N> encrypt_string(const char* str) {
                std::array<char, N> result{};
                for (size_t i = 0; i < N; ++i) result[i] = str[i];
                xtea::encrypt_buffer(result.data(), N, compile_key);
                return result;
            }

            // re-key: derive new key by mixing compile-time key with runtime entropy
            CW_FORCEINLINE void rekey() const {
                uint64_t entropy = CW_RANDOM_RT();
                current_key.k[0] = K0 ^ static_cast<uint32_t>(entropy);
                current_key.k[1] = K1 ^ static_cast<uint32_t>(entropy >> 32);
                current_key.k[2] = K2 ^ static_cast<uint32_t>(entropy * 0x9E3779B9);
                current_key.k[3] = K3 ^ static_cast<uint32_t>((entropy >> 16) * 0x6A09E667);
            }

        public:
            template<size_t... I>
            constexpr layered_encrypted_string(const char (&str)[N], std::index_sequence<I...>)
                : data(encrypt_string(str)), decrypted(false), current_key(compile_key) {}

            constexpr layered_encrypted_string(const char (&str)[N])
                : layered_encrypted_string(str, std::make_index_sequence<N>{}) {}

            CW_NOINLINE const char* get() const {
                CW_COMPILER_BARRIER();
                if (!decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (!decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<char, N>&>(data);
                        xtea::decrypt_buffer(mutable_data.data(), N, current_key);
                        decrypted.store(true, CW_MO_RELAXED);
                    }
                }

                // polymorphic re-encryption every 10 accesses
                uint32_t count = access_count.fetch_add(1, CW_MO_RELAXED);
                if (count > 0 && (count % 10) == 0 && decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<char, N>&>(data);
                        rekey();
                        xtea::encrypt_buffer(mutable_data.data(), N, current_key);
                        xtea::decrypt_buffer(mutable_data.data(), N, current_key);
                    }
                }

                CW_COMPILER_BARRIER();
                return data.data();
            }

            CW_NOINLINE operator const char*() const { return get(); }

            ~layered_encrypted_string() {
                if (decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<char, N>&>(data);
                        xtea::encrypt_buffer(mutable_data.data(), N, current_key);
                        decrypted.store(false, CW_MO_RELAXED);
                    }
                }
            }
        };

        template<size_t N>
        layered_encrypted_string(const char (&)[N]) -> layered_encrypted_string<N>;

        template<size_t N>
        class stack_encrypted_string {
        private:
            char buffer[N];

        public:
            template<size_t M, uint32_t A, uint32_t B, uint32_t C, uint32_t D>
            stack_encrypted_string(const encrypted_string<M, A, B, C, D>& enc) {
                const char* decrypted = enc.get();
                for (size_t i = 0; i < N && i < M; ++i)
                    buffer[i] = decrypted[i];
            }

            const char* get() const { return buffer; }
            operator const char*() const { return buffer; }

            ~stack_encrypted_string() {
                // secure wipe: volatile to prevent optimizer removal
                volatile char* p = buffer;
                for (size_t i = 0; i < N; ++i)
                    p[i] = 0;
                CW_COMPILER_BARRIER();
            }
        };

        template<size_t N,
                 uint32_t K0 = CW_RANDOM_CT(), uint32_t K1 = CW_RANDOM_CT(),
                 uint32_t K2 = CW_RANDOM_CT(), uint32_t K3 = CW_RANDOM_CT()>
        class encrypted_wstring {
        private:
            static constexpr size_t BYTE_LEN = N * sizeof(wchar_t);
            std::array<wchar_t, N> data;
            mutable CW_ATOMIC(bool) decrypted{false};
            mutable CW_MUTEX mutex;

            static constexpr xtea::key128 compile_key = {{K0, K1, K2, K3}};

            // constexpr-safe wchar_t encryption: serialize to bytes, encrypt, deserialize
            static constexpr std::array<wchar_t, N> encrypt_wstring(const wchar_t* str) {
                std::array<uint8_t, BYTE_LEN> bytes{};
                for (size_t i = 0; i < N; ++i) {
                    bytes[i * 2]     = static_cast<uint8_t>(str[i] & 0xFF);
                    bytes[i * 2 + 1] = static_cast<uint8_t>((str[i] >> 8) & 0xFF);
                }
                xtea::encrypt_buffer(bytes.data(), BYTE_LEN, compile_key);
                std::array<wchar_t, N> result{};
                for (size_t i = 0; i < N; ++i) {
                    result[i] = static_cast<wchar_t>(bytes[i * 2])
                              | (static_cast<wchar_t>(bytes[i * 2 + 1]) << 8);
                }
                return result;
            }

        public:
            template<size_t... I>
            constexpr encrypted_wstring(const wchar_t (&str)[N], std::index_sequence<I...>)
                : data(encrypt_wstring(str)), decrypted(false) {}

            constexpr encrypted_wstring(const wchar_t (&str)[N])
                : encrypted_wstring(str, std::make_index_sequence<N>{}) {}

            CW_NOINLINE const wchar_t* get() const {
                CW_COMPILER_BARRIER();
                if (!decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (!decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<wchar_t, N>&>(data);
                        uint8_t bytes[BYTE_LEN];
                        for (size_t i = 0; i < N; ++i) {
                            bytes[i * 2]     = static_cast<uint8_t>(mutable_data[i] & 0xFF);
                            bytes[i * 2 + 1] = static_cast<uint8_t>((mutable_data[i] >> 8) & 0xFF);
                        }
                        xtea::decrypt_buffer(bytes, BYTE_LEN, compile_key);
                        for (size_t i = 0; i < N; ++i) {
                            mutable_data[i] = static_cast<wchar_t>(bytes[i * 2])
                                            | (static_cast<wchar_t>(bytes[i * 2 + 1]) << 8);
                        }
                        decrypted.store(true, CW_MO_RELAXED);
                    }
                }
                CW_COMPILER_BARRIER();
                return data.data();
            }

            CW_NOINLINE operator const wchar_t*() const { return get(); }

            ~encrypted_wstring() {
                if (decrypted.load(CW_MO_RELAXED)) {
                    CW_LOCK_GUARD(mutex);
                    if (decrypted.load(CW_MO_RELAXED)) {
                        auto& mutable_data = const_cast<std::array<wchar_t, N>&>(data);
                        uint8_t bytes[BYTE_LEN];
                        for (size_t i = 0; i < N; ++i) {
                            bytes[i * 2]     = static_cast<uint8_t>(mutable_data[i] & 0xFF);
                            bytes[i * 2 + 1] = static_cast<uint8_t>((mutable_data[i] >> 8) & 0xFF);
                        }
                        xtea::encrypt_buffer(bytes, BYTE_LEN, compile_key);
                        for (size_t i = 0; i < N; ++i) {
                            mutable_data[i] = static_cast<wchar_t>(bytes[i * 2])
                                            | (static_cast<wchar_t>(bytes[i * 2 + 1]) << 8);
                        }
                        decrypted.store(false, CW_MO_RELAXED);
                    }
                }
            }
        };

        template<size_t N>
        encrypted_wstring(const wchar_t (&)[N]) -> encrypted_wstring<N>;
    }

    // string encryption macros
    // constinit ensures compile-time initialization (encrypted data in .rdata, not plaintext)
#define CW_STR(s) \
    static_cast<const char*>(([]() CW_NOINLINE -> const char* { \
        constinit static cloakwork::string_encrypt::encrypted_string<sizeof(s)> enc(s); \
        CW_COMPILER_BARRIER(); \
        return enc.get(); \
    }()))

#define CW_STR_LAYERED(s) \
    static_cast<const char*>(([]() CW_NOINLINE -> const char* { \
        constinit static cloakwork::string_encrypt::layered_encrypted_string<sizeof(s)> enc(s); \
        CW_COMPILER_BARRIER(); \
        return enc.get(); \
    }()))

#define CW_STR_STACK(s) \
    ([&]() CW_NOINLINE { \
        constinit static cloakwork::string_encrypt::encrypted_string<sizeof(s)> enc(s); \
        return cloakwork::string_encrypt::stack_encrypted_string<sizeof(s)>(enc); \
    }())

#define CW_WSTR(s) \
    static_cast<const wchar_t*>(([]() CW_NOINLINE -> const wchar_t* { \
        constinit static cloakwork::string_encrypt::encrypted_wstring<sizeof(s)/sizeof(wchar_t)> enc(s); \
        CW_COMPILER_BARRIER(); \
        return enc.get(); \
    }()))

// stack string builder - builds string char-by-char, never exists as literal in binary
// usage: CW_STACK_STR(name, 'h','e','l','l','o','\0')
#define CW_STACK_STR(name, ...) \
    char name[] = { __VA_ARGS__ }; \
    do { \
        constexpr uint8_t _cw_ssk = static_cast<uint8_t>(CW_RANDOM_CT() | 1); \
        volatile uint8_t* _cw_ssp = reinterpret_cast<volatile uint8_t*>(name); \
        for (size_t _cw_ssi = 0; _cw_ssi < sizeof(name); ++_cw_ssi) \
            _cw_ssp[_cw_ssi] = _cw_ssp[_cw_ssi]; \
        CW_COMPILER_BARRIER(); \
    } while(0)

#else
    #define CW_STR(s) (s)
    #define CW_STR_LAYERED(s) (s)
    #define CW_STR_STACK(s) (s)
    #define CW_WSTR(s) (s)
    #define CW_STACK_STR(name, ...) char name[] = { __VA_ARGS__ }
#endif

#if CW_ENABLE_VALUE_OBFUSCATION

#if CW_KERNEL_MODE
    namespace detail {
        template<typename T>
        struct is_integral_type : std::is_integral<T> {};

        template<typename T>
        struct is_arithmetic_type : std::is_arithmetic<T> {};
    }

    namespace mba {
        // MBA identity: x + y = (x ^ y) + 2 * (x & y)
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T add_mba(T x, T y) {
            return (x ^ y) + ((x & y) << 1);
        }

        // MBA identity: x - y = (x ^ y) - 2 * (~x & y)
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T sub_mba(T x, T y) {
            return (x ^ y) - ((~x & y) << 1);
        }

        // MBA identity: x * 2 = (x ^ (x << 1)) + (x << 1)
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T mul2_mba(T x) {
            return (x ^ (x << 1)) + (x << 1);
        }

        // MBA identity: -x = ~x + 1
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T neg_mba(T x) {
            return add_mba(static_cast<T>(~x), static_cast<T>(1));
        }

        // MBA identity: x & y = ~(~x | ~y)
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T and_mba(T x, T y) {
            return ~(~x | ~y);
        }

        // MBA identity: x | y = ~(~x & ~y)
        template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
        CW_FORCEINLINE constexpr T or_mba(T x, T y) {
            return ~(~x & ~y);
        }
    }

    template<typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
    class obfuscated_value {
    private:
        mutable T value{};
        T xor_key{};
        T add_key{};
        mutable CW_ATOMIC(uint32_t) access_count{0};

        // rotate bits for additional obfuscation
        template<typename U = T, typename = std::enable_if_t<std::is_integral_v<U>>>
        static constexpr U rotate_left(U val, int shift) {
            constexpr int bits = sizeof(U) * 8;
            shift %= bits;
            return (val << shift) | (val >> (bits - shift));
        }

        template<typename U = T, typename = std::enable_if_t<std::is_integral_v<U>>>
        static constexpr U rotate_right(U val, int shift) {
            constexpr int bits = sizeof(U) * 8;
            shift %= bits;
            return (val >> shift) | (val << (bits - shift));
        }

    public:
        obfuscated_value() {
            xor_key = static_cast<T>(CW_RANDOM_RT());
            add_key = static_cast<T>(CW_RANDOM_RT());
            set(static_cast<T>(0));
        }

        obfuscated_value(T val) {
            xor_key = static_cast<T>(CW_RANDOM_RT());
            add_key = static_cast<T>(CW_RANDOM_RT());
            set(val);
        }

        CW_NOINLINE void set(T val) {
            CW_COMPILER_BARRIER();
            if constexpr(std::is_integral_v<T>) {
                T temp = mba::add_mba(val, add_key);
                temp ^= xor_key;
                value = mba::add_mba(temp, static_cast<T>(xor_key & 0xFF));
            } else {
                // floating point: byte-level xor via memcpy to avoid NaN UB
                uint8_t val_bytes[sizeof(T)];
                uint8_t key_bytes[sizeof(T)];
                memcpy(val_bytes, &val, sizeof(T));
                memcpy(key_bytes, &xor_key, sizeof(T));
                for (size_t i = 0; i < sizeof(T); ++i)
                    val_bytes[i] ^= key_bytes[i];
                memcpy(&value, val_bytes, sizeof(T));
            }
            CW_COMPILER_BARRIER();
        }

        CW_NOINLINE T get() const {
            CW_COMPILER_BARRIER();
            if ((++access_count % 1000) == 0) {
                CW_INLINE_CHECK();
            }

            if constexpr(std::is_integral_v<T>) {
                T temp = mba::sub_mba(value, static_cast<T>(xor_key & 0xFF));
                temp ^= xor_key;
                T out = mba::sub_mba(temp, add_key);
                CW_COMPILER_BARRIER();
                return out;
            } else {
                uint8_t val_bytes[sizeof(T)];
                uint8_t key_bytes[sizeof(T)];
                memcpy(val_bytes, &value, sizeof(T));
                memcpy(key_bytes, &xor_key, sizeof(T));
                for (size_t i = 0; i < sizeof(T); ++i)
                    val_bytes[i] ^= key_bytes[i];
                T result;
                memcpy(&result, val_bytes, sizeof(T));
                CW_COMPILER_BARRIER();
                return result;
            }
        }

        CW_FORCEINLINE operator T() const { return get(); }
        CW_FORCEINLINE obfuscated_value& operator=(T val) { set(val); return *this; }
    };

    template<typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    class mba_obfuscated {
    private:
        T encoded{};
        T key1{};
        T key2{};

    public:
        mba_obfuscated() {
            key1 = static_cast<T>(CW_RANDOM_RT());
            key2 = static_cast<T>(CW_RANDOM_RT());
            set(static_cast<T>(0));
        }

        mba_obfuscated(T val) {
            key1 = static_cast<T>(CW_RANDOM_RT());
            key2 = static_cast<T>(CW_RANDOM_RT());
            set(val);
        }

        CW_NOINLINE void set(T val) {
            CW_COMPILER_BARRIER();
            T temp = mba::add_mba(val, key1);
            encoded = temp ^ key2;
            CW_COMPILER_BARRIER();
        }

        CW_NOINLINE T get() const {
            CW_COMPILER_BARRIER();
            T temp = encoded ^ key2;
            T out = mba::sub_mba(temp, key1);
            CW_COMPILER_BARRIER();
            return out;
        }

        CW_FORCEINLINE operator T() const { return get(); }
        CW_FORCEINLINE mba_obfuscated& operator=(T val) { set(val); return *this; }
    };

#else

    template<typename T>
    concept Integral = std::is_integral_v<T>;

    template<typename T>
    concept Arithmetic = std::is_arithmetic_v<T>;

    namespace mba {
        // MBA identity: x + y = (x ^ y) + 2 * (x & y)
        template<Integral T>
        CW_FORCEINLINE constexpr T add_mba(T x, T y) {
            return (x ^ y) + ((x & y) << 1);
        }

        // MBA identity: x - y = (x ^ y) - 2 * (~x & y)
        template<Integral T>
        CW_FORCEINLINE constexpr T sub_mba(T x, T y) {
            return (x ^ y) - ((~x & y) << 1);
        }

        // MBA identity: x * 2 = (x ^ (x << 1)) + (x << 1)
        template<Integral T>
        CW_FORCEINLINE constexpr T mul2_mba(T x) {
            return (x ^ (x << 1)) + (x << 1);
        }

        // MBA identity: -x = ~x + 1
        template<Integral T>
        CW_FORCEINLINE constexpr T neg_mba(T x) {
            return add_mba(static_cast<T>(~x), static_cast<T>(1));
        }

        // MBA identity: x & y = ~(~x | ~y)
        template<Integral T>
        CW_FORCEINLINE constexpr T and_mba(T x, T y) {
            return ~(~x | ~y);
        }

        // MBA identity: x | y = ~(~x & ~y)
        template<Integral T>
        CW_FORCEINLINE constexpr T or_mba(T x, T y) {
            return ~(~x & ~y);
        }
    }

    template<Arithmetic T>
    class obfuscated_value {
    private:
        mutable T value{};
        T xor_key{};
        T add_key{};
        mutable CW_ATOMIC(uint32_t) access_count{0};

        // rotate bits for additional obfuscation
        template<Integral U = T>
        static constexpr U rotate_left(U val, int shift) {
            constexpr int bits = sizeof(U) * 8;
            shift %= bits;
            return (val << shift) | (val >> (bits - shift));
        }

        template<Integral U = T>
        static constexpr U rotate_right(U val, int shift) {
            constexpr int bits = sizeof(U) * 8;
            shift %= bits;
            return (val >> shift) | (val << (bits - shift));
        }

    public:
        obfuscated_value() {
            xor_key = static_cast<T>(CW_RANDOM_RT());
            add_key = static_cast<T>(CW_RANDOM_RT());
            set(static_cast<T>(0));
        }

        obfuscated_value(T val) {
            xor_key = static_cast<T>(CW_RANDOM_RT());
            add_key = static_cast<T>(CW_RANDOM_RT());
            set(val);
        }

        CW_NOINLINE void set(T val) {
            CW_COMPILER_BARRIER();
            if constexpr(Integral<T>) {
                // multi-step obfuscation: mba then xor then mba again for deeper chain
                T temp = mba::add_mba(val, add_key);
                temp ^= xor_key;
                value = mba::add_mba(temp, static_cast<T>(xor_key & 0xFF));
            } else {
                // floating point: byte-level xor via memcpy to avoid NaN UB from bit_cast XOR
                uint8_t val_bytes[sizeof(T)];
                uint8_t key_bytes[sizeof(T)];
                memcpy(val_bytes, &val, sizeof(T));
                memcpy(key_bytes, &xor_key, sizeof(T));
                for (size_t i = 0; i < sizeof(T); ++i)
                    val_bytes[i] ^= key_bytes[i];
                memcpy(&value, val_bytes, sizeof(T));
            }
            CW_COMPILER_BARRIER();
        }

        CW_NOINLINE T get() const {
            CW_COMPILER_BARRIER();
            if ((++access_count % 1000) == 0) {
                CW_INLINE_CHECK();
            }

            if constexpr(Integral<T>) {
                T temp = mba::sub_mba(value, static_cast<T>(xor_key & 0xFF));
                temp ^= xor_key;
                T out = mba::sub_mba(temp, add_key);
                CW_COMPILER_BARRIER();
                return out;
            } else {
                uint8_t val_bytes[sizeof(T)];
                uint8_t key_bytes[sizeof(T)];
                memcpy(val_bytes, &value, sizeof(T));
                memcpy(key_bytes, &xor_key, sizeof(T));
                for (size_t i = 0; i < sizeof(T); ++i)
                    val_bytes[i] ^= key_bytes[i];
                T result;
                memcpy(&result, val_bytes, sizeof(T));
                CW_COMPILER_BARRIER();
                return result;
            }
        }

        CW_FORCEINLINE operator T() const { return get(); }
        CW_FORCEINLINE obfuscated_value& operator=(T val) { set(val); return *this; }
    };

    template<Integral T>
    class mba_obfuscated {
    private:
        T encoded{};
        T key1{};
        T key2{};

    public:
        mba_obfuscated() {
            key1 = static_cast<T>(CW_RANDOM_RT());
            key2 = static_cast<T>(CW_RANDOM_RT());
            set(static_cast<T>(0));
        }

        mba_obfuscated(T val) {
            key1 = static_cast<T>(CW_RANDOM_RT());
            key2 = static_cast<T>(CW_RANDOM_RT());
            set(val);
        }

        CW_NOINLINE void set(T val) {
            CW_COMPILER_BARRIER();
            // encode using MBA: encoded = (val + key1) ^ key2
            T temp = mba::add_mba(val, key1);
            encoded = temp ^ key2;
            CW_COMPILER_BARRIER();
        }

        CW_NOINLINE T get() const {
            CW_COMPILER_BARRIER();
            // decode using MBA: val = (encoded ^ key2) - key1
            T temp = encoded ^ key2;
            T out = mba::sub_mba(temp, key1);
            CW_COMPILER_BARRIER();
            return out;
        }

        CW_FORCEINLINE operator T() const { return get(); }
        CW_FORCEINLINE mba_obfuscated& operator=(T val) { set(val); return *this; }
    };

#endif // CW_KERNEL_MODE (value obfuscation kernel/user split)

    namespace bool_obfuscation {

        // CW_NOINLINE prevents LTCG from constant-folding the result
        template<int N = CW_RAND_CT(0, 7)>
        CW_NOINLINE bool obfuscated_true() {
            volatile int seed = static_cast<int>(reinterpret_cast<uintptr_t>(&seed) & 0xFF) + N;
            CW_COMPILER_BARRIER();

            // stack pointer hash: runtime address through non-invertible transform
            uintptr_t sp = reinterpret_cast<uintptr_t>(&seed);
            uint32_t h = static_cast<uint32_t>(sp) ^ static_cast<uint32_t>(seed);
            h *= 0x45D9F3Bu;
            h ^= h >> 16;
            // h + ~h is always 0xFFFFFFFF regardless of input
            volatile uint32_t complement_sum = h + ~h;
            CW_COMPILER_BARRIER();
            bool result = (complement_sum == 0xFFFFFFFFu);

            // dual-path comparison: same runtime value computed twice independently
            volatile uint32_t path_a = static_cast<uint32_t>(sp & 0xFF);
            uint32_t va = path_a;
            va = (va * 7u + 3u) & 0xFFu;
            volatile uint32_t result_a = va;
            CW_COMPILER_BARRIER();
            volatile uint32_t path_b = static_cast<uint32_t>(sp & 0xFF);
            uint32_t vb = path_b;
            vb = (vb * 7u + 3u) & 0xFFu;
            volatile uint32_t result_b = vb;
            CW_COMPILER_BARRIER();
            result = result && (result_a == result_b);

#if defined(_WIN32)
            // rdtsc XOR with stack: (x | ~x) is always all-ones
            uint64_t tsc = __rdtsc();
            CW_COMPILER_BARRIER();
            uint64_t mixed = tsc ^ sp;
            volatile uint64_t check = mixed | ~mixed;
            CW_COMPILER_BARRIER();
            result = result && (check == ~0ULL);
#endif
            CW_COMPILER_BARRIER();
            return result;
        }

        template<int N = CW_RAND_CT(0, 7)>
        CW_NOINLINE bool obfuscated_false() {
            return !obfuscated_true<N>();
        }

        template<int N = CW_RAND_CT(1, 1000)>
        CW_FORCEINLINE bool obfuscate_bool(bool value) {
            CW_COMPILER_BARRIER();

            // transform: value = (value AND true) OR (false AND anything)
            // mathematically equivalent to just 'value', but harder to analyze
            bool true_val = obfuscated_true<N>();
            bool false_val = obfuscated_false<N + 1>();

            // multiple transformation layers
            bool layer1 = value && true_val;
            bool layer2 = false_val && (!value);
            bool result = layer1 || layer2;

            // additional confusion: XOR with known values
            result = result ^ false_val;  // XOR with false doesn't change value

            CW_COMPILER_BARRIER();
            return result;
        }

        template<uint8_t Key1 = static_cast<uint8_t>(CW_RAND_CT(1, 255)),
                 uint8_t Key2 = static_cast<uint8_t>(CW_RAND_CT(1, 255)),
                 uint8_t Key3 = static_cast<uint8_t>(CW_RAND_CT(1, 255))>
        class obfuscated_bool {
        private:
            mutable uint8_t encoded_primary;
            mutable uint8_t encoded_secondary;
            mutable uint8_t encoded_tertiary;
            mutable CW_ATOMIC(uint32_t) access_count{0};

            // distinct patterns for true/false that don't look like 0/1
            static constexpr uint8_t TRUE_PATTERN = Key1 ^ 0xAA ^ Key2;
            static constexpr uint8_t FALSE_PATTERN = Key1 ^ 0x55 ^ Key3;
            static constexpr uint8_t VERIFY_MASK = Key2 ^ Key3;

            CW_FORCEINLINE void encode(bool value) {
                uint8_t runtime_noise = static_cast<uint8_t>(CW_RANDOM_RT() & 0xF0);

                if (value) {
                    // encode true across multiple bytes with different patterns
                    encoded_primary = TRUE_PATTERN ^ runtime_noise;
                    encoded_secondary = static_cast<uint8_t>(~encoded_primary) ^ Key1;
                    encoded_tertiary = (encoded_primary + encoded_secondary) ^ VERIFY_MASK;
                } else {
                    // encode false with different patterns
                    encoded_primary = FALSE_PATTERN ^ runtime_noise;
                    encoded_secondary = static_cast<uint8_t>(~encoded_primary) ^ Key2;
                    encoded_tertiary = (encoded_primary - encoded_secondary) ^ VERIFY_MASK;
                }
            }

            CW_FORCEINLINE bool decode() const {
                // decode using pattern matching, not simple comparison
                uint8_t reconstructed = encoded_primary ^ (static_cast<uint8_t>(~encoded_primary) ^ Key1);
                uint8_t check = encoded_secondary ^ Key1;

                // verify integrity through tertiary byte
                uint8_t expected_true = (encoded_primary + (static_cast<uint8_t>(~encoded_primary) ^ Key1)) ^ VERIFY_MASK;
                bool is_true_pattern = (encoded_tertiary == expected_true);

                // use MBA to compute final result
                int true_indicator = is_true_pattern ? 1 : 0;
                int one = mba::sub_mba(2, 1);
                return mba::sub_mba(true_indicator, 0) == one;
            }

        public:
            obfuscated_bool() { encode(false); }
            obfuscated_bool(bool value) { encode(value); }

            CW_FORCEINLINE bool get() const {
                // periodic anti-debug check
                if ((++access_count % 500) == 0) {
                    CW_INLINE_CHECK();
                }

                bool raw_value = decode();
                // return through obfuscation layer
                return obfuscate_bool(raw_value);
            }

            CW_FORCEINLINE void set(bool value) {
                encode(value);
            }

            CW_FORCEINLINE operator bool() const { return get(); }
            CW_FORCEINLINE obfuscated_bool& operator=(bool value) { set(value); return *this; }

            CW_FORCEINLINE obfuscated_bool operator!() const {
                return obfuscated_bool(!get());
            }

            CW_FORCEINLINE obfuscated_bool operator&&(bool other) const {
                return obfuscated_bool(get() && other);
            }

            CW_FORCEINLINE obfuscated_bool operator||(bool other) const {
                return obfuscated_bool(get() || other);
            }
        };
    }

    #define CW_TRUE (cloakwork::bool_obfuscation::obfuscated_true<CW_RAND_CT(1, 1000)>())
    #define CW_FALSE (cloakwork::bool_obfuscation::obfuscated_false<CW_RAND_CT(1, 1000)>())
    #define CW_BOOL(x) (cloakwork::bool_obfuscation::obfuscate_bool<CW_RAND_CT(1, 1000)>(x))

    #define CW_ADD(a, b) (cloakwork::mba::add_mba((a), (b)))
    #define CW_SUB(a, b) (cloakwork::mba::sub_mba((a), (b)))
    #define CW_AND(a, b) (cloakwork::mba::and_mba((a), (b)))
    #define CW_OR(a, b) (cloakwork::mba::or_mba((a), (b)))

#else
    template<typename T>
    class obfuscated_value {
    private:
        T value{};
    public:
        obfuscated_value() = default;
        obfuscated_value(T val) : value(val) {}
        CW_FORCEINLINE void set(T val) { value = val; }
        CW_FORCEINLINE T get() const { return value; }
        CW_FORCEINLINE operator T() const { return value; }
        CW_FORCEINLINE obfuscated_value& operator=(T val) { value = val; return *this; }
    };

    template<typename T>
    class mba_obfuscated {
    private:
        T value{};
    public:
        mba_obfuscated() = default;
        mba_obfuscated(T val) : value(val) {}
        CW_FORCEINLINE void set(T val) { value = val; }
        CW_FORCEINLINE T get() const { return value; }
        CW_FORCEINLINE operator T() const { return value; }
        CW_FORCEINLINE mba_obfuscated& operator=(T val) { value = val; return *this; }
    };

    #define CW_ADD(a, b) ((a) + (b))
    #define CW_SUB(a, b) ((a) - (b))
    #define CW_AND(a, b) ((a) & (b))
    #define CW_OR(a, b) ((a) | (b))

    namespace bool_obfuscation {
        template<int N = 0> inline bool obfuscated_true() { return true; }
        template<int N = 0> inline bool obfuscated_false() { return false; }
        template<int N = 0> inline bool obfuscate_bool(bool value) { return value; }

        class obfuscated_bool {
        private:
            bool value;
        public:
            obfuscated_bool() : value(false) {}
            obfuscated_bool(bool val) : value(val) {}
            CW_FORCEINLINE bool get() const { return value; }
            CW_FORCEINLINE void set(bool val) { value = val; }
            CW_FORCEINLINE operator bool() const { return value; }
            CW_FORCEINLINE obfuscated_bool& operator=(bool val) { value = val; return *this; }
            CW_FORCEINLINE obfuscated_bool operator!() const { return obfuscated_bool(!value); }
            CW_FORCEINLINE obfuscated_bool operator&&(bool other) const { return obfuscated_bool(value && other); }
            CW_FORCEINLINE obfuscated_bool operator||(bool other) const { return obfuscated_bool(value || other); }
        };
    }

    #define CW_TRUE (true)
    #define CW_FALSE (false)
    #define CW_BOOL(x) (x)
#endif

#if CW_ENABLE_CONTROL_FLOW
    namespace control_flow {

        // decompiler-resistant opaque predicates
        // these use patterns that ida/hex-rays cannot simplify:
        // memory aliasing, environment queries, pointer arithmetic, mixed math

        namespace opaque_detail {
            // predicate 0: hash stack pointer through non-trivial computation
            // the compiler cannot determine the stack address at compile time,
            // and the multiply-xor-shift chain is non-invertible for static analysis
            CW_NOINLINE bool stack_hash_true(int seed) {
                volatile int anchor = seed;
                uintptr_t sp = reinterpret_cast<uintptr_t>(&anchor);
                CW_COMPILER_BARRIER();
                // non-trivial hash: multiply by large prime, xor-shift, check parity of popcount
                uint32_t h = static_cast<uint32_t>(sp);
                h ^= static_cast<uint32_t>(seed);
                h *= 0x45D9F3Bu;
                h ^= h >> 16;
                h *= 0x119DE1F3u;
                h ^= h >> 13;
                // popcount of any 32-bit value added to its complement is always 32
                uint32_t complement = ~h;
                volatile uint32_t combined = h + complement;
                CW_COMPILER_BARRIER();
                // h + ~h == 0xFFFFFFFF for any h, so combined is always 0xFFFFFFFF
                return combined == 0xFFFFFFFFu;
            }

            // predicate 1: rdtsc XOR with stack address
            // both values are runtime-only; the XOR and modular arithmetic
            // produce a result the optimizer cannot statically resolve
            CW_NOINLINE bool tsc_stack_true() {
#if defined(_WIN32)
                volatile int anchor = 0;
                uintptr_t sp = reinterpret_cast<uintptr_t>(&anchor);
                uint64_t tsc = __rdtsc();
                CW_COMPILER_BARRIER();
                uint64_t mixed = tsc ^ sp;
                // (x | ~x) is always all-ones for any x
                volatile uint64_t check = mixed | ~mixed;
                CW_COMPILER_BARRIER();
                return check == ~0ULL;
#elif CW_KERNEL_MODE
                volatile int anchor = 0;
                uintptr_t sp = reinterpret_cast<uintptr_t>(&anchor);
                uint64_t tsc = __rdtsc();
                CW_COMPILER_BARRIER();
                uint64_t mixed = tsc ^ sp;
                volatile uint64_t check = mixed | ~mixed;
                CW_COMPILER_BARRIER();
                return check == ~0ULL;
#else
                return true;
#endif
            }

            // predicate 2: thread ID through non-invertible transform
            // GetCurrentThreadId is a runtime call, and the transform chain
            // ensures the optimizer cannot prove the final comparison
            CW_NOINLINE bool tid_transform_true() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                uint32_t tid = GetCurrentThreadId();
                CW_COMPILER_BARRIER();
                // Collatz-like transform - non-invertible, runtime-dependent
                uint32_t v = tid | 0x100u; // ensure nonzero
                volatile uint32_t orig = v;
                for (volatile int i = 0; i < 3; ++i) {
                    v = (v & 1) ? (v * 3u + 1u) : (v >> 1);
                }
                CW_COMPILER_BARRIER();
                // (orig ^ orig) is always 0, but compiler can't prove it
                // through the volatile indirection and loop side effects
                volatile uint32_t self_xor = orig ^ orig;
                return self_xor == 0;
#elif CW_KERNEL_MODE
                uintptr_t tid = HandleToULong(PsGetCurrentThreadId());
                CW_COMPILER_BARRIER();
                uint32_t v = static_cast<uint32_t>(tid) | 0x100u;
                volatile uint32_t orig = v;
                for (volatile int i = 0; i < 3; ++i) {
                    v = (v & 1) ? (v * 3u + 1u) : (v >> 1);
                }
                CW_COMPILER_BARRIER();
                volatile uint32_t self_xor = orig ^ orig;
                return self_xor == 0;
#else
                return true;
#endif
            }

            // predicate 3: multiply-accumulate with runtime stack entropy
            // uses the address of a local as entropy, runs it through a
            // sequence of operations that always produces a known bit pattern
            CW_NOINLINE bool mac_entropy_true(int seed) {
                volatile int anchor = seed;
                uint32_t addr_bits = static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(&anchor));
                CW_COMPILER_BARRIER();
                // Feistel-like round: split, mix, recombine
                uint16_t lo = static_cast<uint16_t>(addr_bits);
                uint16_t hi = static_cast<uint16_t>(addr_bits >> 16);
                uint16_t mixed = hi ^ (lo * 0x7Fu + static_cast<uint16_t>(seed));
                // (x - x) is always 0, but through volatile the compiler
                // cannot fold the subtract away
                volatile uint16_t a = mixed;
                volatile uint16_t b = mixed;
                CW_COMPILER_BARRIER();
                volatile int16_t diff = static_cast<int16_t>(a - b);
                return diff == 0;
            }

            // predicate 4: compare two independently computed representations of
            // the same runtime value; compiler cannot prove equality across
            // volatile stores and reloads with arithmetic in between
            CW_NOINLINE bool dual_path_true() {
                volatile int anchor = 42;
                uintptr_t base = reinterpret_cast<uintptr_t>(&anchor);
                CW_COMPILER_BARRIER();
                // path A: lower 8 bits through multiply-add
                volatile uint32_t path_a = static_cast<uint32_t>(base & 0xFF);
                uint32_t va = path_a;
                va = (va * 7u + 3u) & 0xFFu;
                va = (va * 11u + 5u) & 0xFFu;
                volatile uint32_t result_a = va;
                CW_COMPILER_BARRIER();
                // path B: same computation on same input
                volatile uint32_t path_b = static_cast<uint32_t>(base & 0xFF);
                uint32_t vb = path_b;
                vb = (vb * 7u + 3u) & 0xFFu;
                vb = (vb * 11u + 5u) & 0xFFu;
                volatile uint32_t result_b = vb;
                CW_COMPILER_BARRIER();
                return result_a == result_b;
            }

            // predicate 5: use ReturnAddress as entropy source;
            // the return address is purely runtime and varies per call site
            CW_NOINLINE bool retaddr_true() {
#if defined(_MSC_VER)
                uintptr_t ra = reinterpret_cast<uintptr_t>(_ReturnAddress());
#elif defined(__GNUC__)
                uintptr_t ra = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#else
                uintptr_t ra = 1;
#endif
                CW_COMPILER_BARRIER();
                // any value XOR'd with itself is zero
                volatile uintptr_t v = ra;
                CW_COMPILER_BARRIER();
                volatile uintptr_t check = v ^ v;
                CW_COMPILER_BARRIER();
                return check == 0;
            }

            // predicate 6: process/module base address through hash
            CW_NOINLINE bool module_hash_true() {
#if defined(_WIN32) && !CW_KERNEL_MODE
                uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
                CW_COMPILER_BARRIER();
                uint32_t h = static_cast<uint32_t>(base);
                h *= 0x85EBCA6Bu;
                h ^= h >> 13;
                h *= 0xC2B2AE35u;
                // (h & 0) is always 0 - but the hash chain prevents
                // the optimizer from seeing through to the constant
                volatile uint32_t masked = h & 0u;
                CW_COMPILER_BARRIER();
                return masked == 0;
#elif CW_KERNEL_MODE
                uintptr_t proc = reinterpret_cast<uintptr_t>(PsGetCurrentProcess());
                CW_COMPILER_BARRIER();
                uint32_t h = static_cast<uint32_t>(proc);
                h *= 0x85EBCA6Bu;
                h ^= h >> 13;
                h *= 0xC2B2AE35u;
                volatile uint32_t masked = h & 0u;
                CW_COMPILER_BARRIER();
                return masked == 0;
#else
                return true;
#endif
            }

            // predicate 7: rdtsc difference is always non-negative
            // two consecutive rdtsc calls always produce t2 >= t1 on the same core,
            // and the subtraction through volatile prevents constant folding
            CW_NOINLINE bool tsc_delta_true() {
#if defined(_WIN32)
                uint64_t t1 = __rdtsc();
                CW_COMPILER_BARRIER();
                volatile int dummy = 0;
                (void)dummy;
                CW_COMPILER_BARRIER();
                uint64_t t2 = __rdtsc();
                CW_COMPILER_BARRIER();
                // t2 - t1 is always >= 0 (unsigned), and never == UINT64_MAX
                // in practice; but more importantly the compiler cannot
                // determine the actual values of t1 or t2
                volatile uint64_t delta = t2 - t1;
                // delta < some huge value is always true
                return delta < 0xFFFFFFFF00000000ULL;
#else
                return true;
#endif
            }
        }

        // rotate between predicate types per call site using compile-time random
        // CW_NOINLINE prevents LTCG from inlining and resolving the predicate chain
        template<int N = CW_RAND_CT(0, 7)>
        CW_NOINLINE bool opaque_true() {
            volatile int seed = static_cast<int>(reinterpret_cast<uintptr_t>(&seed) & 0xFF) + N;
            CW_COMPILER_BARRIER();

            // compile-time selection of predicate combination
            constexpr int primary = N % 8;
            constexpr int secondary = (N * 3 + 1) % 8;

            bool result;
            if constexpr (primary == 0) result = opaque_detail::stack_hash_true(seed);
            else if constexpr (primary == 1) result = opaque_detail::tsc_stack_true();
            else if constexpr (primary == 2) result = opaque_detail::tid_transform_true();
            else if constexpr (primary == 3) result = opaque_detail::mac_entropy_true(seed);
            else if constexpr (primary == 4) result = opaque_detail::dual_path_true();
            else if constexpr (primary == 5) result = opaque_detail::retaddr_true();
            else if constexpr (primary == 6) result = opaque_detail::module_hash_true();
            else result = opaque_detail::tsc_delta_true();

            // chain with a second predicate for extra confusion
            if constexpr (secondary == 0) result = result && opaque_detail::stack_hash_true(seed + 1);
            else if constexpr (secondary == 1) result = result && opaque_detail::tsc_stack_true();
            else if constexpr (secondary == 2) result = result && opaque_detail::tid_transform_true();
            else if constexpr (secondary == 3) result = result && opaque_detail::mac_entropy_true(seed + 1);
            else if constexpr (secondary == 4) result = result && opaque_detail::dual_path_true();
            else if constexpr (secondary == 5) result = result && opaque_detail::retaddr_true();
            else if constexpr (secondary == 6) result = result && opaque_detail::module_hash_true();
            else result = result && opaque_detail::tsc_delta_true();

            CW_COMPILER_BARRIER();
            return result;
        }

        template<int N = CW_RAND_CT(0, 7)>
        CW_NOINLINE bool opaque_false() {
            // negate a true predicate - same decompiler resistance
            return !opaque_true<N>();
        }

        // control flow flattening via switch-case state machine
        // generates a real dispatcher that IDA/Hex-Rays shows as a state machine
        // state transitions are XOR-encoded with a compile-time key
        template<typename Func,
                 uint32_t XK = CW_RANDOM_CT(),
                 uint32_t S0 = CW_RAND_CT(10, 99),
                 uint32_t S1 = CW_RAND_CT(100, 199),
                 uint32_t S2 = CW_RAND_CT(200, 299),
                 uint32_t S3 = CW_RAND_CT(300, 399),
                 uint32_t S4 = CW_RAND_CT(400, 499),
                 uint32_t S5 = CW_RAND_CT(500, 599),
                 uint32_t S6 = CW_RAND_CT(600, 699),
                 uint32_t S7 = CW_RAND_CT(700, 799)>
        class flattened_flow {
        public:
            template<typename... Args>
            CW_NOINLINE auto execute(Func func, Args&&... args) -> decltype(func(std::forward<Args>(args)...)) {
                using ResultType = decltype(func(std::forward<Args>(args)...));
                ResultType result{};

                // XOR-encoded state variable - decoded inside the switch
                volatile uint32_t state = S0 ^ XK;
                volatile uint32_t iter = 0;
                CW_COMPILER_BARRIER();

                while (iter < 64) {
                    uint32_t decoded = static_cast<uint32_t>(state) ^ XK;
                    CW_COMPILER_BARRIER();
                    ++iter;

                    switch (decoded) {
                        case S0: {
                            volatile int anchor = static_cast<int>(iter);
                            CW_COMPILER_BARRIER();
                            state = S1 ^ XK;
                            break;
                        }
                        case S1: {
                            if (opaque_true<>()) {
                                state = S2 ^ XK;
                            } else {
                                state = S5 ^ XK; // fake path
                            }
                            break;
                        }
                        case S2: {
                            result = func(std::forward<Args>(args)...);
                            state = S3 ^ XK;
                            break;
                        }
                        case S3: {
                            if (opaque_true<>()) {
                                state = S4 ^ XK; // exit
                            } else {
                                state = S6 ^ XK; // fake path
                            }
                            break;
                        }
                        case S4: {
                            iter = 64; // break the loop
                            break;
                        }
                        case S5: {
                            // fake computation block 1
                            volatile int junk = 42;
                            junk = (junk * 3 + 1) ^ static_cast<int>(iter);
                            CW_COMPILER_BARRIER();
                            state = S1 ^ XK;
                            break;
                        }
                        case S6: {
                            // fake computation block 2
                            volatile float junk = 2.718f;
                            junk = junk * 3.14f + static_cast<float>(iter);
                            CW_COMPILER_BARRIER();
                            state = S3 ^ XK;
                            break;
                        }
                        case S7: {
                            // fake loop block
                            volatile int acc = 0;
                            for (volatile int i = 0; i < 3; ++i) acc += i;
                            CW_COMPILER_BARRIER();
                            state = S0 ^ XK;
                            break;
                        }
                        default: {
                            // unknown state recovery
                            state = S4 ^ XK;
                            break;
                        }
                    }
                    CW_COMPILER_BARRIER();
                }

                return result;
            }
        };

        template<typename T>
        CW_FORCEINLINE T indirect_branch(T value) {
            T result = value;
            int selector = static_cast<int>(CW_RANDOM_RT() % 5);
            CW_COMPILER_BARRIER();

            // create multiple paths that all lead to same result
            switch(selector) {
                case 0:
                    result = result ^ 0 ^ 0;
                    break;
                case 1:
                    result = (result * 1) / 1;
                    break;
                case 2:
                    result = result + 0 - 0;
                    break;
                case 3:
                    result = result | 0 & ~0;
                    break;
                case 4:
                    result = result << 0 >> 0;
                    break;
            }

            return result;
        }
    }

    #define CW_IF(cond) \
        if(cloakwork::control_flow::opaque_true<>() && (cond))

    #define CW_ELSE \
        else if(cloakwork::control_flow::opaque_true<>())

    #define CW_FLATTEN(func, ...) \
        cloakwork::control_flow::flattened_flow<decltype(func)>().execute(func, __VA_ARGS__)

    //
    // converts if/else/loop control flow into a dispatcher loop with
    // encrypted state transitions, dead blocks, and opaque predicates.
    // produces decompiler-hostile output that IDA/Hex-Rays shows as a
    // complex state machine rather than the original structured code.
    //
    // usage:
    //   int result = CW_FLAT_FUNC(int)
    //       CW_FLAT_VARS(int x = 0; int y = 0;)
    //       CW_FLAT_ENTRY(0)
    //   CW_FLAT_BEGIN
    //       CW_FLAT_BLOCK(0)
    //           x = input * 2;
    //           CW_FLAT_GOTO(1)
    //       CW_FLAT_BLOCK(1)
    //           CW_FLAT_IF(x > 50, 2, 3)
    //       CW_FLAT_BLOCK(2)
    //           CW_FLAT_RETURN(x)
    //       CW_FLAT_BLOCK(3)
    //           x += 10;
    //           CW_FLAT_GOTO(1)
    //   CW_FLAT_END;
    //
    // every block MUST end with a transition: GOTO, IF, RETURN, or EXIT.
    // block IDs are arbitrary unsigned integers (0-65535 recommended).

    namespace cfg_flatten {

        // compile-time state derivation - maps block IDs to pseudo-random
        // case values using a keyed splitmix32-like hash.
        // produces well-distributed values with no collisions for typical inputs.
        static constexpr uint32_t derive_state(uint32_t block_id, uint32_t seed) {
            uint32_t h = block_id + seed;
            h ^= h >> 16;
            h *= 0x45D9F3Bu;
            h ^= h >> 16;
            h *= 0x119DE1F3u;
            h ^= h >> 13;
            return (h | 1u); // ensure non-zero and odd (sparse jump table)
        }

        // dead state derivation - different multiplier to avoid overlap with user states
        static constexpr uint32_t derive_dead(uint32_t index, uint32_t seed) {
            uint32_t h = (index + 0xDEAD0000u) ^ seed;
            h ^= h >> 15;
            h *= 0x2C1B3C6Du;
            h ^= h >> 15;
            h *= 0x297A2D39u;
            h ^= h >> 13;
            return (h | 1u);
        }

        // noinline dispatch wrapper - prevents LTCG/WPO from seeing through
        // the flattened code and reconstructing the original CFG
        template<typename F>
        CW_NOINLINE auto execute(F&& f) -> decltype(f()) {
            CW_COMPILER_BARRIER();
            auto result = f();
            CW_COMPILER_BARRIER();
            return result;
        }

        template<typename F>
        CW_NOINLINE void execute_void(F&& f) {
            CW_COMPILER_BARRIER();
            f();
            CW_COMPILER_BARRIER();
        }
    }

    // derive obfuscated case value from block ID using per-region seed
    #define _CW_FLAT_STATE(id) \
        (cloakwork::cfg_flatten::derive_state(static_cast<uint32_t>(id), _cw_flat_seed))

    // derive dead block case value
    #define _CW_FLAT_DEAD(n) \
        (cloakwork::cfg_flatten::derive_dead(static_cast<uint32_t>(n), _cw_flat_seed))

    // begin a flattened function returning ret_type.
    // use as: auto result = CW_FLAT_FUNC(int) ... CW_FLAT_END;
    #define CW_FLAT_FUNC(ret_type) \
        cloakwork::cfg_flatten::execute([&]() -> ret_type { \
            constexpr uint32_t _cw_flat_seed = \
                static_cast<uint32_t>(__LINE__) * 0x45D9F3Bu + \
                static_cast<uint32_t>(__COUNTER__) * 0x9E3779B9u; \
            ret_type _cw_flat_res{}; \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st;

    // begin a void flattened function.
    // use as: CW_FLAT_VOID ... CW_FLAT_VOID_END;
    #define CW_FLAT_VOID \
        cloakwork::cfg_flatten::execute_void([&]() { \
            constexpr uint32_t _cw_flat_seed = \
                static_cast<uint32_t>(__LINE__) * 0x45D9F3Bu + \
                static_cast<uint32_t>(__COUNTER__) * 0x9E3779B9u; \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st;

    // declare shared variables accessible across all blocks.
    // must appear between CW_FLAT_FUNC/CW_FLAT_VOID and CW_FLAT_ENTRY.
    #define CW_FLAT_VARS(...) __VA_ARGS__

    // set the entry block ID. must appear before CW_FLAT_BEGIN.
    #define CW_FLAT_ENTRY(id) \
        _cw_flat_st = _CW_FLAT_STATE(id);

    // begin the dispatch loop. inserts dead blocks automatically.
    // dead blocks form an unreachable cycle that inflates the CFG
    // and confuses path enumeration in decompilers.
    #define CW_FLAT_BEGIN \
        CW_COMPILER_BARRIER(); \
        while (_cw_flat_run && _cw_flat_it < 16384u) { \
            uint32_t _cw_flat_d = static_cast<uint32_t>(_cw_flat_st); \
            ++_cw_flat_it; \
            CW_COMPILER_BARRIER(); \
            switch (_cw_flat_d) { \
                /* dead block 0: hash-like computation */ \
                case _CW_FLAT_DEAD(0): { \
                    volatile uint32_t _dh = 0x811C9DC5u; \
                    _dh ^= static_cast<uint32_t>(_cw_flat_it); \
                    _dh *= 0x01000193u; \
                    _dh ^= _dh >> 16; \
                    _cw_flat_st = _CW_FLAT_DEAD(1); \
                    break; \
                } \
                /* dead block 1: accumulator loop */ \
                case _CW_FLAT_DEAD(1): { \
                    volatile int _da = 0; \
                    for (volatile int _di = 0; _di < 3; ++_di) \
                        _da = _da * 31 + _di; \
                    _cw_flat_st = _CW_FLAT_DEAD(2); \
                    break; \
                } \
                /* dead block 2: xorshift junk */ \
                case _CW_FLAT_DEAD(2): { \
                    volatile uint32_t _dx = _cw_flat_it; \
                    _dx ^= _dx << 13; \
                    _dx ^= _dx >> 17; \
                    _dx ^= _dx << 5; \
                    _cw_flat_st = _CW_FLAT_DEAD(3); \
                    break; \
                } \
                /* dead block 3: conditional cycle back */ \
                case _CW_FLAT_DEAD(3): { \
                    volatile int _dc = static_cast<int>(_cw_flat_it) & 0xFF; \
                    if (_dc > 128) { _cw_flat_st = _CW_FLAT_DEAD(4); } \
                    else { _cw_flat_st = _CW_FLAT_DEAD(0); } \
                    break; \
                } \
                /* dead block 4: stack entropy */ \
                case _CW_FLAT_DEAD(4): { \
                    volatile int _ds; \
                    volatile uintptr_t _dp = reinterpret_cast<uintptr_t>(&_ds); \
                    _ds = static_cast<int>(_dp & 0xFFu); \
                    _cw_flat_st = _CW_FLAT_DEAD(5); \
                    break; \
                } \
                /* dead block 5: multiply-accumulate */ \
                case _CW_FLAT_DEAD(5): { \
                    volatile uint32_t _dm = _cw_flat_it * 0x45D9F3Bu; \
                    _dm ^= _dm >> 16; \
                    _dm += 0x119DE1F3u; \
                    _cw_flat_st = _CW_FLAT_DEAD(0); \
                    break; \
                } \
                /* sentinel - closed by first CW_FLAT_BLOCK */ \
                case _CW_FLAT_DEAD(0xFF): {

    // start a user block with the given ID.
    // every block must end with GOTO, IF, RETURN, or EXIT.
    #define CW_FLAT_BLOCK(id) \
                break; \
                } \
                case _CW_FLAT_STATE(id): {

    // unconditional transition to target block
    #define CW_FLAT_GOTO(id) \
                    CW_COMPILER_BARRIER(); \
                    _cw_flat_st = _CW_FLAT_STATE(id); \
                    CW_COMPILER_BARRIER(); \
                    break;

    // obfuscated transition - adds fake dead-block branch via opaque predicate.
    // use this for critical transitions to maximize IDA confusion.
    #define CW_FLAT_GOTO_OBF(id) \
                    CW_COMPILER_BARRIER(); \
                    if (cloakwork::control_flow::opaque_true<>()) { \
                        _cw_flat_st = _CW_FLAT_STATE(id); \
                    } else { \
                        _cw_flat_st = _CW_FLAT_DEAD(0); \
                    } \
                    CW_COMPILER_BARRIER(); \
                    break;

    // conditional transition - dispatches to true_id or false_id based on condition
    #define CW_FLAT_IF(cond, true_id, false_id) \
                    CW_COMPILER_BARRIER(); \
                    _cw_flat_st = (cond) \
                        ? static_cast<uint32_t>(_CW_FLAT_STATE(true_id)) \
                        : static_cast<uint32_t>(_CW_FLAT_STATE(false_id)); \
                    CW_COMPILER_BARRIER(); \
                    break;

    // obfuscated conditional - routes through volatile to prevent branch folding
    #define CW_FLAT_IF_OBF(cond, true_id, false_id) \
                    CW_COMPILER_BARRIER(); \
                    { \
                        volatile bool _cw_cond = (cond); \
                        CW_COMPILER_BARRIER(); \
                        if (_cw_cond) { \
                            if (cloakwork::control_flow::opaque_true<>()) \
                                _cw_flat_st = _CW_FLAT_STATE(true_id); \
                            else \
                                _cw_flat_st = _CW_FLAT_DEAD(0); \
                        } else { \
                            if (cloakwork::control_flow::opaque_true<>()) \
                                _cw_flat_st = _CW_FLAT_STATE(false_id); \
                            else \
                                _cw_flat_st = _CW_FLAT_DEAD(1); \
                        } \
                    } \
                    CW_COMPILER_BARRIER(); \
                    break;

    // return a value and exit the flattened function
    #define CW_FLAT_RETURN(val) \
                    CW_COMPILER_BARRIER(); \
                    _cw_flat_res = (val); \
                    _cw_flat_run = false; \
                    CW_COMPILER_BARRIER(); \
                    break;

    // exit without returning a value (for void functions or default-return)
    #define CW_FLAT_EXIT() \
                    CW_COMPILER_BARRIER(); \
                    _cw_flat_run = false; \
                    CW_COMPILER_BARRIER(); \
                    break;

    // multi-way branch - flattened switch replacement.
    // evaluates expr once, transitions to the matching block.
    // pairs is a sequence of (value, block_id) checks with a default.
    // usage: CW_FLAT_SWITCH(x, 0,blk_a, 1,blk_b, 2,blk_c, default_blk)
    // (last argument is the default block)
    #define CW_FLAT_SWITCH2(expr, v0,b0, v1,b1, def_blk) \
                    CW_COMPILER_BARRIER(); \
                    { \
                        auto _cw_sw = (expr); \
                        if (_cw_sw == (v0)) _cw_flat_st = _CW_FLAT_STATE(b0); \
                        else if (_cw_sw == (v1)) _cw_flat_st = _CW_FLAT_STATE(b1); \
                        else _cw_flat_st = _CW_FLAT_STATE(def_blk); \
                    } \
                    CW_COMPILER_BARRIER(); \
                    break;

    #define CW_FLAT_SWITCH3(expr, v0,b0, v1,b1, v2,b2, def_blk) \
                    CW_COMPILER_BARRIER(); \
                    { \
                        auto _cw_sw = (expr); \
                        if (_cw_sw == (v0)) _cw_flat_st = _CW_FLAT_STATE(b0); \
                        else if (_cw_sw == (v1)) _cw_flat_st = _CW_FLAT_STATE(b1); \
                        else if (_cw_sw == (v2)) _cw_flat_st = _CW_FLAT_STATE(b2); \
                        else _cw_flat_st = _CW_FLAT_STATE(def_blk); \
                    } \
                    CW_COMPILER_BARRIER(); \
                    break;

    #define CW_FLAT_SWITCH4(expr, v0,b0, v1,b1, v2,b2, v3,b3, def_blk) \
                    CW_COMPILER_BARRIER(); \
                    { \
                        auto _cw_sw = (expr); \
                        if (_cw_sw == (v0)) _cw_flat_st = _CW_FLAT_STATE(b0); \
                        else if (_cw_sw == (v1)) _cw_flat_st = _CW_FLAT_STATE(b1); \
                        else if (_cw_sw == (v2)) _cw_flat_st = _CW_FLAT_STATE(b2); \
                        else if (_cw_sw == (v3)) _cw_flat_st = _CW_FLAT_STATE(b3); \
                        else _cw_flat_st = _CW_FLAT_STATE(def_blk); \
                    } \
                    CW_COMPILER_BARRIER(); \
                    break;

    // close the dispatch loop and return. use after last CW_FLAT_BLOCK.
    #define CW_FLAT_END \
                break; \
                } \
                default: { \
                    _cw_flat_run = false; \
                    break; \
                } \
            } \
            CW_COMPILER_BARRIER(); \
        } \
        return _cw_flat_res; \
    })

    // close a void flattened function
    #define CW_FLAT_VOID_END \
                break; \
                } \
                default: { \
                    _cw_flat_run = false; \
                    break; \
                } \
            } \
            CW_COMPILER_BARRIER(); \
        } \
    })

    //
    // wraps arbitrary code in an encrypted state machine dispatcher.
    // the user's code becomes one state among dead blocks and opaque
    // predicates. produces the same decompiler-hostile output as the
    // manual CW_FLAT_* API but without requiring manual block decomposition.
    //
    // usage:
    //   int result = CW_PROTECT(int, {
    //       if (x > 10) return x * 2;
    //       return x + 5;
    //   });
    //
    //   CW_PROTECT_VOID({
    //       do_something();
    //   });
    //
    // the code block is executed inside a lambda ([&] capture), so:
    //   - `return` exits the block, not the enclosing function
    //   - all local variables from the enclosing scope are accessible
    //   - ret_type must not contain unparenthesized commas
    //     (use a typedef for std::pair<int,int> etc.)
    //
    // for maximum protection with manual control flow decomposition,
    // use the CW_FLAT_* API instead.

    #define CW_PROTECT(ret_type, ...) \
        cloakwork::cfg_flatten::execute([&]() -> ret_type { \
            constexpr uint32_t _cw_flat_seed = \
                static_cast<uint32_t>(__LINE__) * 0x45D9F3Bu + \
                static_cast<uint32_t>(__COUNTER__) * 0x9E3779B9u; \
            ret_type _cw_flat_res{}; \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st = _CW_FLAT_STATE(0); \
            CW_COMPILER_BARRIER(); \
            while (_cw_flat_run && _cw_flat_it < 16384u) { \
                uint32_t _cw_flat_d = static_cast<uint32_t>(_cw_flat_st); \
                ++_cw_flat_it; \
                CW_COMPILER_BARRIER(); \
                switch (_cw_flat_d) { \
                    case _CW_FLAT_DEAD(0): { \
                        volatile uint32_t _dh = 0x811C9DC5u; \
                        _dh ^= static_cast<uint32_t>(_cw_flat_it); \
                        _dh *= 0x01000193u; \
                        _dh ^= _dh >> 16; \
                        _cw_flat_st = _CW_FLAT_DEAD(1); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(1): { \
                        volatile int _da = 0; \
                        for (volatile int _di = 0; _di < 3; ++_di) \
                            _da = _da * 31 + _di; \
                        _cw_flat_st = _CW_FLAT_DEAD(2); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(2): { \
                        volatile uint32_t _dx = _cw_flat_it; \
                        _dx ^= _dx << 13; \
                        _dx ^= _dx >> 17; \
                        _dx ^= _dx << 5; \
                        _cw_flat_st = _CW_FLAT_DEAD(3); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(3): { \
                        volatile int _dc = static_cast<int>(_cw_flat_it) & 0xFF; \
                        if (_dc > 128) { _cw_flat_st = _CW_FLAT_DEAD(4); } \
                        else { _cw_flat_st = _CW_FLAT_DEAD(0); } \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(4): { \
                        volatile int _ds; \
                        volatile uintptr_t _dp = reinterpret_cast<uintptr_t>(&_ds); \
                        _ds = static_cast<int>(_dp & 0xFFu); \
                        _cw_flat_st = _CW_FLAT_DEAD(5); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(5): { \
                        volatile uint32_t _dm = _cw_flat_it * 0x45D9F3Bu; \
                        _dm ^= _dm >> 16; \
                        _dm += 0x119DE1F3u; \
                        _cw_flat_st = _CW_FLAT_DEAD(0); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(0): { \
                        CW_COMPILER_BARRIER(); \
                        volatile uint32_t _ep = _cw_flat_it; \
                        _ep ^= _ep << 7; \
                        if (cloakwork::control_flow::opaque_true<>()) { \
                            _cw_flat_st = _CW_FLAT_STATE(1); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_DEAD(0); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(1): { \
                        CW_COMPILER_BARRIER(); \
                        volatile uint32_t _op = (_cw_flat_it | 2u); \
                        if ((_op * (_op - 1u)) & 1u) { \
                            _cw_flat_st = _CW_FLAT_DEAD(3); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_STATE(2); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(2): { \
                        CW_COMPILER_BARRIER(); \
                        _cw_flat_res = [&]() -> ret_type { __VA_ARGS__ }(); \
                        CW_COMPILER_BARRIER(); \
                        _cw_flat_st = _CW_FLAT_STATE(3); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(3): { \
                        CW_COMPILER_BARRIER(); \
                        if (cloakwork::control_flow::opaque_true<>()) { \
                            _cw_flat_st = _CW_FLAT_STATE(4); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_DEAD(5); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(4): { \
                        _cw_flat_run = false; \
                        break; \
                    } \
                    default: { \
                        _cw_flat_run = false; \
                        break; \
                    } \
                } \
                CW_COMPILER_BARRIER(); \
            } \
            return _cw_flat_res; \
        })

    #define CW_PROTECT_VOID(...) \
        cloakwork::cfg_flatten::execute_void([&]() { \
            constexpr uint32_t _cw_flat_seed = \
                static_cast<uint32_t>(__LINE__) * 0x45D9F3Bu + \
                static_cast<uint32_t>(__COUNTER__) * 0x9E3779B9u; \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st = _CW_FLAT_STATE(0); \
            CW_COMPILER_BARRIER(); \
            while (_cw_flat_run && _cw_flat_it < 16384u) { \
                uint32_t _cw_flat_d = static_cast<uint32_t>(_cw_flat_st); \
                ++_cw_flat_it; \
                CW_COMPILER_BARRIER(); \
                switch (_cw_flat_d) { \
                    case _CW_FLAT_DEAD(0): { \
                        volatile uint32_t _dh = 0x811C9DC5u; \
                        _dh ^= static_cast<uint32_t>(_cw_flat_it); \
                        _dh *= 0x01000193u; \
                        _dh ^= _dh >> 16; \
                        _cw_flat_st = _CW_FLAT_DEAD(1); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(1): { \
                        volatile int _da = 0; \
                        for (volatile int _di = 0; _di < 3; ++_di) \
                            _da = _da * 31 + _di; \
                        _cw_flat_st = _CW_FLAT_DEAD(2); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(2): { \
                        volatile uint32_t _dx = _cw_flat_it; \
                        _dx ^= _dx << 13; \
                        _dx ^= _dx >> 17; \
                        _dx ^= _dx << 5; \
                        _cw_flat_st = _CW_FLAT_DEAD(3); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(3): { \
                        volatile int _dc = static_cast<int>(_cw_flat_it) & 0xFF; \
                        if (_dc > 128) { _cw_flat_st = _CW_FLAT_DEAD(4); } \
                        else { _cw_flat_st = _CW_FLAT_DEAD(0); } \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(4): { \
                        volatile int _ds; \
                        volatile uintptr_t _dp = reinterpret_cast<uintptr_t>(&_ds); \
                        _ds = static_cast<int>(_dp & 0xFFu); \
                        _cw_flat_st = _CW_FLAT_DEAD(5); \
                        break; \
                    } \
                    case _CW_FLAT_DEAD(5): { \
                        volatile uint32_t _dm = _cw_flat_it * 0x45D9F3Bu; \
                        _dm ^= _dm >> 16; \
                        _dm += 0x119DE1F3u; \
                        _cw_flat_st = _CW_FLAT_DEAD(0); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(0): { \
                        CW_COMPILER_BARRIER(); \
                        volatile uint32_t _ep = _cw_flat_it; \
                        _ep ^= _ep << 7; \
                        if (cloakwork::control_flow::opaque_true<>()) { \
                            _cw_flat_st = _CW_FLAT_STATE(1); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_DEAD(0); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(1): { \
                        CW_COMPILER_BARRIER(); \
                        volatile uint32_t _op = (_cw_flat_it | 2u); \
                        if ((_op * (_op - 1u)) & 1u) { \
                            _cw_flat_st = _CW_FLAT_DEAD(3); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_STATE(2); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(2): { \
                        CW_COMPILER_BARRIER(); \
                        [&]() { __VA_ARGS__ }(); \
                        CW_COMPILER_BARRIER(); \
                        _cw_flat_st = _CW_FLAT_STATE(3); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(3): { \
                        CW_COMPILER_BARRIER(); \
                        if (cloakwork::control_flow::opaque_true<>()) { \
                            _cw_flat_st = _CW_FLAT_STATE(4); \
                        } else { \
                            _cw_flat_st = _CW_FLAT_DEAD(5); \
                        } \
                        CW_COMPILER_BARRIER(); \
                        break; \
                    } \
                    case _CW_FLAT_STATE(4): { \
                        _cw_flat_run = false; \
                        break; \
                    } \
                    default: { \
                        _cw_flat_run = false; \
                        break; \
                    } \
                } \
                CW_COMPILER_BARRIER(); \
            } \
        })

#else
    namespace control_flow {
        template<int N = 0> inline bool opaque_true() { return true; }
        template<int N = 0> inline bool opaque_false() { return false; }
        template<typename T> inline T indirect_branch(T value) { return value; }
    }
    #define CW_IF(cond) if(cond)
    #define CW_ELSE else
    #define CW_FLATTEN(func, ...) func(__VA_ARGS__)

    #define _CW_FLAT_STATE(id) static_cast<uint32_t>(id)
    #define _CW_FLAT_DEAD(n) (0xFFFF0000u + static_cast<uint32_t>(n))

    #define CW_FLAT_FUNC(ret_type) \
        [&]() -> ret_type { \
            ret_type _cw_flat_res{}; \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st;

    #define CW_FLAT_VOID \
        [&]() { \
            volatile bool _cw_flat_run = true; \
            volatile uint32_t _cw_flat_it = 0; \
            volatile uint32_t _cw_flat_st;

    #define CW_FLAT_VARS(...) __VA_ARGS__
    #define CW_FLAT_ENTRY(id) _cw_flat_st = _CW_FLAT_STATE(id);

    #define CW_FLAT_BEGIN \
        while (_cw_flat_run && _cw_flat_it++ < 16384u) { \
            switch (static_cast<uint32_t>(_cw_flat_st)) { \
                case _CW_FLAT_DEAD(0xFF): {

    #define CW_FLAT_BLOCK(id) break; } case _CW_FLAT_STATE(id): {
    #define CW_FLAT_GOTO(id) _cw_flat_st = _CW_FLAT_STATE(id); break;
    #define CW_FLAT_GOTO_OBF(id) CW_FLAT_GOTO(id)
    #define CW_FLAT_IF(cond, true_id, false_id) \
        _cw_flat_st = (cond) ? _CW_FLAT_STATE(true_id) : _CW_FLAT_STATE(false_id); break;
    #define CW_FLAT_IF_OBF(cond, true_id, false_id) CW_FLAT_IF(cond, true_id, false_id)
    #define CW_FLAT_RETURN(val) _cw_flat_res = (val); _cw_flat_run = false; break;
    #define CW_FLAT_EXIT() _cw_flat_run = false; break;
    #define CW_FLAT_SWITCH2(expr, v0,b0, v1,b1, def) \
        { auto _s=(expr); if(_s==(v0)) _cw_flat_st=_CW_FLAT_STATE(b0); \
          else if(_s==(v1)) _cw_flat_st=_CW_FLAT_STATE(b1); \
          else _cw_flat_st=_CW_FLAT_STATE(def); } break;
    #define CW_FLAT_SWITCH3(expr, v0,b0, v1,b1, v2,b2, def) \
        { auto _s=(expr); if(_s==(v0)) _cw_flat_st=_CW_FLAT_STATE(b0); \
          else if(_s==(v1)) _cw_flat_st=_CW_FLAT_STATE(b1); \
          else if(_s==(v2)) _cw_flat_st=_CW_FLAT_STATE(b2); \
          else _cw_flat_st=_CW_FLAT_STATE(def); } break;
    #define CW_FLAT_SWITCH4(expr, v0,b0, v1,b1, v2,b2, v3,b3, def) \
        { auto _s=(expr); if(_s==(v0)) _cw_flat_st=_CW_FLAT_STATE(b0); \
          else if(_s==(v1)) _cw_flat_st=_CW_FLAT_STATE(b1); \
          else if(_s==(v2)) _cw_flat_st=_CW_FLAT_STATE(b2); \
          else if(_s==(v3)) _cw_flat_st=_CW_FLAT_STATE(b3); \
          else _cw_flat_st=_CW_FLAT_STATE(def); } break;

    #define CW_FLAT_END \
        break; } default: { _cw_flat_run = false; break; } \
        } } return _cw_flat_res; }()

    #define CW_FLAT_VOID_END \
        break; } default: { _cw_flat_run = false; break; } \
        } } }()

    #define CW_PROTECT(ret_type, ...) \
        [&]() -> ret_type { __VA_ARGS__ }()

    #define CW_PROTECT_VOID(...) \
        [&]() { __VA_ARGS__ }()

#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION

    template<typename Func>
    class obfuscated_call {
    private:
        // xtea-encrypted function pointer (reuses cipher from string_encrypt)
        uint8_t encrypted_addr[sizeof(uintptr_t)];
        string_encrypt::xtea::key128 ptr_key;

        // decoy array with randomized size and position
        static constexpr size_t MAX_DECOYS = 16;
        uintptr_t decoys[MAX_DECOYS];
        size_t decoy_count;
        size_t real_index;

        CW_FORCEINLINE void encrypt_ptr(Func* ptr) {
            uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
            memcpy(encrypted_addr, &addr, sizeof(uintptr_t));
            string_encrypt::xtea::encrypt_buffer(encrypted_addr, sizeof(uintptr_t), ptr_key);
        }

        CW_FORCEINLINE Func* decrypt_ptr() const {
            uint8_t temp[sizeof(uintptr_t)];
            memcpy(temp, encrypted_addr, sizeof(uintptr_t));
            string_encrypt::xtea::decrypt_buffer(temp, sizeof(uintptr_t), ptr_key);
            uintptr_t addr;
            memcpy(&addr, temp, sizeof(uintptr_t));
            return reinterpret_cast<Func*>(addr);
        }

    public:
        obfuscated_call(Func* func) {
            ptr_key.k[0] = static_cast<uint32_t>(CW_RANDOM_RT());
            ptr_key.k[1] = static_cast<uint32_t>(CW_RANDOM_RT());
            ptr_key.k[2] = static_cast<uint32_t>(CW_RANDOM_RT());
            ptr_key.k[3] = static_cast<uint32_t>(CW_RANDOM_RT());

            encrypt_ptr(func);

            decoy_count = 4 + (CW_RANDOM_RT() % (MAX_DECOYS - 4 + 1));
            real_index = CW_RANDOM_RT() % decoy_count;

            for (size_t i = 0; i < decoy_count; ++i) {
                decoys[i] = CW_RANDOM_RT();
            }
            uintptr_t addr;
            memcpy(&addr, encrypted_addr, sizeof(uintptr_t));
            decoys[real_index] = addr;
        }

        template<typename... Args>
        CW_FORCEINLINE auto operator()(Args&&... args) {
            static CW_ATOMIC(uint32_t) call_count{0};
            if ((++call_count % 100) == 0) {
                CW_INLINE_CHECK();
            }

            Func* real_func = decrypt_ptr();
            return real_func(std::forward<Args>(args)...);
        }
    };
#else
    template<typename Func>
    class obfuscated_call {
    private:
        Func* func_ptr;
    public:
        obfuscated_call(Func* func) : func_ptr(func) {}
        template<typename... Args>
        CW_FORCEINLINE auto operator()(Args&&... args) {
            return func_ptr(std::forward<Args>(args)...);
        }
    };
#endif

#if CW_ENABLE_DATA_HIDING
    namespace data_hiding {

        template<typename T, size_t Chunks = 8>
        class scattered_value {
        private:
            static_assert(Chunks > 1 && Chunks <= 64, "Chunks must be between 2 and 64");
            static_assert(sizeof(T) >= Chunks || Chunks == 2, "Too many chunks for type size");

            struct chunk_holder {
                std::unique_ptr<uint8_t[]> data;
                size_t size;
                uint8_t xor_key;

                chunk_holder() : size(0), xor_key(0) {}
            };

            std::array<chunk_holder, Chunks> chunks;
            mutable CW_MUTEX mutex;

            void scatter_data(const T& value) {
                const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
                size_t bytes_per_chunk = sizeof(T) / Chunks;
                size_t remainder = sizeof(T) % Chunks;
                size_t byte_idx = 0;

                for(size_t i = 0; i < Chunks; ++i) {
                    size_t chunk_size = bytes_per_chunk + (i < remainder ? 1 : 0);
                    chunks[i].size = chunk_size;
                    chunks[i].data = std::make_unique<uint8_t[]>(chunk_size);
                    chunks[i].xor_key = static_cast<uint8_t>(CW_RANDOM_RT());

                    for(size_t j = 0; j < chunk_size && byte_idx < sizeof(T); ++j, ++byte_idx) {
                        chunks[i].data[j] = bytes[byte_idx] ^ chunks[i].xor_key;
                    }
                }
            }

        public:
            scattered_value() {
                T default_value{};
                scatter_data(default_value);
            }

            scattered_value(const T& value) {
                scatter_data(value);
            }

            CW_FORCEINLINE T get() const {
                CW_LOCK_GUARD(mutex);
                T result;
                uint8_t* result_bytes = reinterpret_cast<uint8_t*>(&result);
                size_t byte_idx = 0;

                for(size_t i = 0; i < Chunks; ++i) {
                    for(size_t j = 0; j < chunks[i].size && byte_idx < sizeof(T); ++j, ++byte_idx) {
                        result_bytes[byte_idx] = chunks[i].data[j] ^ chunks[i].xor_key;
                    }
                }

                return result;
            }

            CW_FORCEINLINE operator T() const { return get(); }

            CW_FORCEINLINE void set(const T& value) {
                CW_LOCK_GUARD(mutex);
                scatter_data(value);
            }
        };

        template<Arithmetic T>
        class polymorphic_value {
        private:
            mutable T value;
            mutable CW_ATOMIC(uint32_t) mutation_count{0};
            mutable CW_MUTEX mutex;

            CW_FORCEINLINE void mutate() const {
                if(++mutation_count % 100 == 0) {
                    CW_LOCK_GUARD(mutex);
                    T temp = value;

                    uint32_t transform = CW_RANDOM_RT() % 4;
                    CW_COMPILER_BARRIER();

                    switch(transform) {
                        case 0:
                            if constexpr(Integral<T> && sizeof(T) <= sizeof(uint64_t)) {
                                if constexpr(sizeof(T) == 8) {
                                    uint64_t bits = std::bit_cast<uint64_t>(temp);
                                    bits = ~bits;
                                    value = std::bit_cast<T>(bits);
                                    bits = std::bit_cast<uint64_t>(value);
                                    bits = ~bits;
                                    value = std::bit_cast<T>(bits);
                                } else if constexpr(sizeof(T) == 4) {
                                    uint32_t bits = std::bit_cast<uint32_t>(temp);
                                    bits = ~bits;
                                    value = std::bit_cast<T>(bits);
                                    bits = std::bit_cast<uint32_t>(value);
                                    bits = ~bits;
                                    value = std::bit_cast<T>(bits);
                                } else if constexpr(sizeof(T) == 2) {
                                    uint16_t bits = std::bit_cast<uint16_t>(temp);
                                    bits = ~bits;
                                    value = std::bit_cast<T>(bits);
                                } else {
                                    value = temp;
                                }
                            }
                            break;
                        case 1:
                            if constexpr(std::is_unsigned_v<T> && Integral<T>) {
                                value = std::rotl(value, 1);
                                value = std::rotr(value, 1);
                            }
                            break;
                        case 2:
                            if constexpr(Arithmetic<T>) {
                                T key = static_cast<T>(mutation_count.load());
                                value = temp + key;
                                value = value - key;
                            }
                            break;
                        case 3:
                            break;
                    }
                }
            }

        public:
            polymorphic_value() : value{} {}
            polymorphic_value(T val) : value(val) {}

            CW_FORCEINLINE T get() const {
                mutate();
                return value;
            }

            CW_FORCEINLINE void set(T val) {
                value = val;
                mutate();
            }

            CW_FORCEINLINE operator T() const { return get(); }
        };
    }
#else
    namespace data_hiding {
        template<typename T, size_t Chunks = 8>
        class scattered_value {
        private:
            T value;
        public:
            scattered_value() : value{} {}
            scattered_value(const T& val) : value(val) {}
            CW_FORCEINLINE T get() const { return value; }
            CW_FORCEINLINE operator T() const { return value; }
            CW_FORCEINLINE void set(const T& val) { value = val; }
        };

        template<typename T>
        class polymorphic_value {
        private:
            T value;
        public:
            polymorphic_value() : value{} {}
            polymorphic_value(T val) : value(val) {}
            CW_FORCEINLINE T get() const { return value; }
            CW_FORCEINLINE void set(T val) { value = val; }
            CW_FORCEINLINE operator T() const { return value; }
        };
    }
#endif

#if CW_ENABLE_METAMORPHIC
    namespace metamorphic {

#if defined(_WIN64) && !CW_KERNEL_MODE
        // polymorphic thunk generator - allocates executable memory and generates
        // randomized x64 instruction sequences that ultimately call the real function
        namespace thunk_gen {
            // random nop-equivalent instructions for x64
            CW_FORCEINLINE size_t emit_junk_instruction(uint8_t* buf, uint64_t entropy) {
                uint32_t choice = static_cast<uint32_t>(entropy % 8);
                switch (choice) {
                    case 0: buf[0] = 0x90; return 1;  // nop
                    case 1: buf[0] = 0x66; buf[1] = 0x90; return 2;  // 66 nop
                    case 2: buf[0] = 0x0F; buf[1] = 0x1F; buf[2] = 0x00; return 3;  // nop dword [rax]
                    case 3: // lea rax, [rax+0]
                        buf[0] = 0x48; buf[1] = 0x8D; buf[2] = 0x40; buf[3] = 0x00;
                        return 4;
                    case 4: // xchg reg, reg (same register = nop)
                        buf[0] = 0x48; buf[1] = 0x87; buf[2] = 0xC0;  // xchg rax, rax
                        return 3;
                    case 5: // push rbx; pop rbx
                        buf[0] = 0x53; buf[1] = 0x5B;
                        return 2;
                    case 6: // push rcx; pop rcx
                        buf[0] = 0x51; buf[1] = 0x59;
                        return 2;
                    default: // test rax, rax (flags-only, doesn't change regs)
                        buf[0] = 0x48; buf[1] = 0x85; buf[2] = 0xC0;
                        return 3;
                }
            }

            // generate a thunk that jumps to the real function with randomized padding
            CW_FORCEINLINE uint8_t* generate_thunk(void* target) {
                uint8_t* page = reinterpret_cast<uint8_t*>(
                    VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
                if (!page) return nullptr;

                size_t offset = 0;

                // emit 3-8 random junk instructions before the real jump
                uint32_t junk_count = 3 + (static_cast<uint32_t>(CW_RANDOM_RT()) % 6);
                for (uint32_t i = 0; i < junk_count && offset < 200; ++i) {
                    offset += emit_junk_instruction(page + offset, CW_RANDOM_RT());
                }

                // mov rax, <target_address> (48 B8 XX XX XX XX XX XX XX XX)
                page[offset++] = 0x48;
                page[offset++] = 0xB8;
                *reinterpret_cast<uint64_t*>(page + offset) = reinterpret_cast<uint64_t>(target);
                offset += 8;

                // emit 1-3 more junk instructions
                uint32_t junk_count2 = 1 + (static_cast<uint32_t>(CW_RANDOM_RT()) % 3);
                for (uint32_t i = 0; i < junk_count2 && offset < 250; ++i) {
                    offset += emit_junk_instruction(page + offset, CW_RANDOM_RT());
                }

                // jmp rax (FF E0)
                page[offset++] = 0xFF;
                page[offset++] = 0xE0;

                // fill rest with int3 for safety
                for (size_t i = offset; i < 4096; ++i)
                    page[i] = 0xCC;

                return page;
            }

            CW_FORCEINLINE void free_thunk(uint8_t* thunk) {
                if (thunk) VirtualFree(thunk, 0, MEM_RELEASE);
            }
        }
#endif

        template<typename Func>
        class metamorphic_function {
        private:
            Func* real_func;
            mutable CW_ATOMIC(uint32_t) call_count{0};

#if defined(_WIN64) && !CW_KERNEL_MODE
            static constexpr uint32_t REGEN_INTERVAL = 1000;
            mutable uint8_t* thunk = nullptr;
            mutable CW_MUTEX mutex;
#endif

        public:
            metamorphic_function(std::initializer_list<Func*> funcs) {
                real_func = *funcs.begin();

#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk = thunk_gen::generate_thunk(reinterpret_cast<void*>(real_func));
#endif
            }

            metamorphic_function(Func* func) : real_func(func) {
#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk = thunk_gen::generate_thunk(reinterpret_cast<void*>(real_func));
#endif
            }

            ~metamorphic_function() {
#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk_gen::free_thunk(thunk);
#endif
            }

            metamorphic_function(const metamorphic_function&) = delete;
            metamorphic_function& operator=(const metamorphic_function&) = delete;

            metamorphic_function(metamorphic_function&& other) noexcept
                : real_func(other.real_func), call_count(other.call_count.load()) {
#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk = other.thunk;
                other.thunk = nullptr;
#endif
            }

            template<typename... Args>
            CW_FORCEINLINE auto operator()(Args&&... args) const {
                uint32_t count = ++call_count;

#if defined(_WIN64) && !CW_KERNEL_MODE
                // regenerate thunk every N calls - different machine code each time
                if (thunk && (count % REGEN_INTERVAL) == 0) {
                    CW_LOCK_GUARD(mutex);
                    uint8_t* old_thunk = thunk;
                    uint8_t* new_thunk = thunk_gen::generate_thunk(reinterpret_cast<void*>(real_func));
                    if (new_thunk) {
                        const_cast<uint8_t*&>(thunk) = new_thunk;
                        thunk_gen::free_thunk(old_thunk);
                    }
                }

                if (thunk) {
                    auto thunk_fn = reinterpret_cast<Func*>(thunk);
                    return thunk_fn(std::forward<Args>(args)...);
                }
#endif

                return real_func(std::forward<Args>(args)...);
            }
        };
    }
#else
    namespace metamorphic {
        template<typename Func>
        class metamorphic_function {
        private:
            Func* func_ptr;
        public:
            metamorphic_function(Func* func) : func_ptr(func) {}
            metamorphic_function(std::initializer_list<Func*> funcs) : func_ptr(*funcs.begin()) {}
            template<typename... Args>
            CW_FORCEINLINE auto operator()(Args&&... args) const {
                return func_ptr(std::forward<Args>(args)...);
            }
        };
    }
#endif

#if CW_ENABLE_IMPORT_HIDING
    namespace imports {

        namespace detail {
            // validate PE header structure with bounds checking
            CW_FORCEINLINE bool validate_pe_header(void* module, IMAGE_NT_HEADERS** out_nt, uint32_t* out_image_size) {
                auto dos = static_cast<IMAGE_DOS_HEADER*>(module);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

                // e_lfanew must be positive and within reasonable bounds
                if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) return false;

                auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);

#if CW_KERNEL_MODE
                if (!MmIsAddressValid(nt)) return false;
#endif
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

                uint32_t image_size = nt->OptionalHeader.SizeOfImage;
                if (image_size == 0 || image_size > 0x7FFFFFFF) return false;

                *out_nt = nt;
                *out_image_size = image_size;
                return true;
            }

            // validate that an RVA falls within image bounds
            CW_FORCEINLINE bool rva_in_bounds(uint32_t rva, uint32_t size, uint32_t image_size) {
                uint64_t end = static_cast<uint64_t>(rva) + static_cast<uint64_t>(size);
                return rva < image_size && end <= static_cast<uint64_t>(image_size);
            }

            // parse "DllName.FunctionName" forwarded export string and resolve recursively
            CW_FORCEINLINE void* resolve_forwarded_export(const char* forward_str) {
                // find the dot separator
                const char* dot = forward_str;
                while (*dot && *dot != '.') ++dot;
                if (!*dot) return nullptr;

                // build module name with ".dll" suffix
                // forward_str is like "NTDLL.RtlInitUnicodeString"
                char module_name[256];
                size_t mod_len = static_cast<size_t>(dot - forward_str);
                if (mod_len >= sizeof(module_name) - 5) return nullptr;

                for (size_t i = 0; i < mod_len; ++i)
                    module_name[i] = forward_str[i];
                module_name[mod_len] = '.';
                module_name[mod_len + 1] = 'd';
                module_name[mod_len + 2] = 'l';
                module_name[mod_len + 3] = 'l';
                module_name[mod_len + 4] = '\0';

                const char* func_name = dot + 1;

                // resolve the forwarding target module and function
                uint32_t mod_hash = hash::fnv1a_runtime_ci(module_name);
                uint32_t func_hash = hash::fnv1a_runtime(func_name);

                // avoid infinite recursion - we use the public functions declared below
                // but since they're in the same namespace, forward declaration isn't needed
                // we just call through the namespace
                void* target_mod = nullptr;

                // inline PEB walk to avoid circular dependency with getModuleBase
#if defined(_WIN32) && !CW_KERNEL_MODE
#ifdef _WIN64
                auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
                auto peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
                if (!peb || !peb->Ldr) return nullptr;

                auto ldr = peb->Ldr;
                auto head = &ldr->InMemoryOrderModuleList;
                for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
                    auto entry = CONTAINING_RECORD(curr, cloakwork_internal::CW_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    if (!entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) continue;
                    if (hash::fnv1a_runtime_ci_w2a(entry->BaseDllName.Buffer) == mod_hash) {
                        target_mod = entry->DllBase;
                        break;
                    }
                }
#endif
                if (!target_mod) return nullptr;

                // now resolve the function in the target module (non-recursive getProcAddress inline)
                IMAGE_NT_HEADERS* nt = nullptr;
                uint32_t image_size = 0;
                if (!validate_pe_header(target_mod, &nt, &image_size)) return nullptr;

                auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exp_dir.VirtualAddress == 0) return nullptr;
                if (!rva_in_bounds(exp_dir.VirtualAddress, exp_dir.Size, image_size)) return nullptr;

                auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                    reinterpret_cast<uint8_t*>(target_mod) + exp_dir.VirtualAddress);

                if (!rva_in_bounds(exports->AddressOfNames, exports->NumberOfNames * 4, image_size)) return nullptr;
                if (!rva_in_bounds(exports->AddressOfNameOrdinals, exports->NumberOfNames * 2, image_size)) return nullptr;
                if (!rva_in_bounds(exports->AddressOfFunctions, exports->NumberOfFunctions * 4, image_size)) return nullptr;

                auto names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(target_mod) + exports->AddressOfNames);
                auto ordinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(target_mod) + exports->AddressOfNameOrdinals);
                auto functions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(target_mod) + exports->AddressOfFunctions);

                for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
                    if (!rva_in_bounds(names[i], 1, image_size)) continue;
                    auto name = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(target_mod) + names[i]);
                    if (hash::fnv1a_runtime(name) == func_hash) {
                        uint16_t ordinal = ordinals[i];
                        if (ordinal >= exports->NumberOfFunctions) return nullptr;
                        uint32_t func_rva = functions[ordinal];
                        // don't follow another forward - one level is enough
                        return reinterpret_cast<uint8_t*>(target_mod) + func_rva;
                    }
                }

                return nullptr;
            }
        }

        CW_FORCEINLINE void* getModuleBase(uint32_t moduleHash) {
#if CW_KERNEL_MODE
            // kernel mode: first try ntoskrnl via RtlPcToFileHeader
            typedef PVOID (*RtlPcToFileHeaderFn)(PVOID PcValue, PVOID* BaseOfImage);
            static RtlPcToFileHeaderFn RtlPcToFileHeader = nullptr;
            static bool rtl_resolved = false;

            if (!rtl_resolved) {
                UNICODE_STRING func_name;
                RtlInitUnicodeString(&func_name, L"RtlPcToFileHeader");
                RtlPcToFileHeader = reinterpret_cast<RtlPcToFileHeaderFn>(
                    MmGetSystemRoutineAddress(&func_name));
                rtl_resolved = true;
            }

            // check if we're looking for ntoskrnl
            if (RtlPcToFileHeader) {
                PVOID ntoskrnl_base = nullptr;
                RtlPcToFileHeader(reinterpret_cast<PVOID>(RtlPcToFileHeader), &ntoskrnl_base);

                if (ntoskrnl_base) {
                    IMAGE_NT_HEADERS* nt = nullptr;
                    uint32_t image_size = 0;
                    if (detail::validate_pe_header(ntoskrnl_base, &nt, &image_size)) {
                        uint32_t ntoskrnl_hashes[] = {
                            hash::fnv1a_ci("ntoskrnl.exe", 12),
                            hash::fnv1a_ci("ntkrnlpa.exe", 12),
                            hash::fnv1a_ci("ntkrnlmp.exe", 12),
                        };

                        for (auto h : ntoskrnl_hashes) {
                            if (h == moduleHash) return ntoskrnl_base;
                        }
                    }
                }
            }

            // walk PsLoadedModuleList for arbitrary driver lookup
            // PsLoadedModuleList is an undocumented but well-known exported symbol
            typedef PLIST_ENTRY PsLoadedModuleListPtr;
            static PsLoadedModuleListPtr PsLoadedModuleList = nullptr;
            static bool pslml_resolved = false;

            if (!pslml_resolved) {
                UNICODE_STRING name;
                RtlInitUnicodeString(&name, L"PsLoadedModuleList");
                PsLoadedModuleList = reinterpret_cast<PsLoadedModuleListPtr>(
                    MmGetSystemRoutineAddress(&name));
                pslml_resolved = true;
            }

            if (PsLoadedModuleList && MmIsAddressValid(PsLoadedModuleList)) {
                auto head = PsLoadedModuleList;
                for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
                    if (!MmIsAddressValid(curr)) break;

                    auto entry = CONTAINING_RECORD(curr,
                        cloakwork_internal::KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                    if (!MmIsAddressValid(entry)) continue;
                    if (!entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) continue;
                    if (!MmIsAddressValid(entry->BaseDllName.Buffer)) continue;

                    uint32_t modHash = hash::fnv1a_runtime_ci_w2a(entry->BaseDllName.Buffer);
                    if (modHash == moduleHash) {
                        return entry->DllBase;
                    }
                }
            }

            return nullptr;

#elif defined(_WIN32)
            __try {
#ifdef _WIN64
                auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
                auto peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
                if (!peb || !peb->Ldr) return nullptr;

                auto ldr = peb->Ldr;
                auto head = &ldr->InMemoryOrderModuleList;

                for (auto curr = head->Flink; curr != head; curr = curr->Flink) {
                    auto entry = CONTAINING_RECORD(curr, cloakwork_internal::CW_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    if (!entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) continue;

                    uint32_t modHash = hash::fnv1a_runtime_ci_w2a(entry->BaseDllName.Buffer);
                    if (modHash == moduleHash) {
                        return entry->DllBase;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
#endif
            return nullptr;
        }

        CW_FORCEINLINE void* walkExportTable(void* module, uint32_t funcHash) {
            IMAGE_NT_HEADERS* nt = nullptr;
            uint32_t image_size = 0;
            if (!detail::validate_pe_header(module, &nt, &image_size)) return nullptr;

            auto& export_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (export_entry.VirtualAddress == 0 || export_entry.Size == 0) return nullptr;

            // validate export directory RVA + size within image bounds
            if (!detail::rva_in_bounds(export_entry.VirtualAddress, export_entry.Size, image_size))
                return nullptr;

            auto base = reinterpret_cast<uint8_t*>(module);
            auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + export_entry.VirtualAddress);

#if CW_KERNEL_MODE
            if (!MmIsAddressValid(exports)) return nullptr;
#endif

            // validate all three table RVAs
            if (!detail::rva_in_bounds(exports->AddressOfNames,
                exports->NumberOfNames * sizeof(uint32_t), image_size))
                return nullptr;
            if (!detail::rva_in_bounds(exports->AddressOfNameOrdinals,
                exports->NumberOfNames * sizeof(uint16_t), image_size))
                return nullptr;
            if (!detail::rva_in_bounds(exports->AddressOfFunctions,
                exports->NumberOfFunctions * sizeof(uint32_t), image_size))
                return nullptr;

            auto names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
            auto ordinals = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
            auto functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

            for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
                if (!detail::rva_in_bounds(names[i], 1, image_size)) continue;

                auto name = reinterpret_cast<const char*>(base + names[i]);
#if CW_KERNEL_MODE
                if (!MmIsAddressValid(const_cast<char*>(name))) continue;
#endif

                if (hash::fnv1a_runtime(name) == funcHash) {
                    // bounds-check ordinal before using as index into functions array
                    uint16_t ordinal = ordinals[i];
                    if (ordinal >= exports->NumberOfFunctions) return nullptr;

                    uint32_t func_rva = functions[ordinal];

                    // check for forwarded export using 64-bit arithmetic to prevent overflow
                    uint64_t export_start = static_cast<uint64_t>(export_entry.VirtualAddress);
                    uint64_t export_end = export_start + static_cast<uint64_t>(export_entry.Size);

                    if (static_cast<uint64_t>(func_rva) >= export_start &&
                        static_cast<uint64_t>(func_rva) < export_end) {
#if CW_KERNEL_MODE
                        // kernel mode: don't follow forwarded exports
                        return nullptr;
#else
                        auto forward_str = reinterpret_cast<const char*>(base + func_rva);
                        return detail::resolve_forwarded_export(forward_str);
#endif
                    }

                    return base + func_rva;
                }
            }

            return nullptr;
        }

        CW_FORCEINLINE void* getProcAddress(void* module, uint32_t funcHash) {
            if (!module) return nullptr;

#if CW_KERNEL_MODE
            if (!MmIsAddressValid(module)) return nullptr;
            return walkExportTable(module, funcHash);
#elif defined(_WIN32)
            __try {
                return walkExportTable(module, funcHash);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
#else
            return nullptr;
#endif
        }

        template<uint32_t ModuleHash, uint32_t FuncHash>
        CW_FORCEINLINE void* getCachedImport() {
            static void* cached = nullptr;
            if (!cached) {
                void* mod = getModuleBase(ModuleHash);
                if (mod) cached = getProcAddress(mod, FuncHash);
            }
            return cached;
        }
    }

    #define CW_IMPORT(mod, func) \
        reinterpret_cast<decltype(&func)>( \
            cloakwork::imports::getCachedImport<CW_HASH_CI(mod), CW_HASH(#func)>())

    #define CW_IMPORT_WIDE(mod, func) \
        reinterpret_cast<decltype(&func)>( \
            cloakwork::imports::getCachedImport<CW_HASH_WIDE(mod), CW_HASH(#func)>())
#else
    namespace imports {
        inline void* getModuleBase(uint32_t) { return nullptr; }
        inline void* getProcAddress(void*, uint32_t) { return nullptr; }
    }
    #define CW_IMPORT(mod, func) (&func)
    #define CW_IMPORT_WIDE(mod, func) (&func)
#endif

#if CW_ENABLE_SYSCALLS
    namespace syscall {

        static constexpr uint32_t SYSCALL_ERROR = UINT32_MAX;

        // extract syscall number from ntdll stub with halo's gate fallback
        CW_FORCEINLINE uint32_t getSyscallNumber(uint32_t funcHash) {
#if defined(_WIN32) && !CW_KERNEL_MODE
            __try {
                void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                if (!ntdll) return SYSCALL_ERROR;

                auto func = reinterpret_cast<uint8_t*>(imports::getProcAddress(ntdll, funcHash));
                if (!func) return SYSCALL_ERROR;

                // standard pattern: mov r10, rcx; mov eax, <number>
                // bytes: 4C 8B D1 B8 XX XX XX XX
                if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
                    uint32_t number = *reinterpret_cast<uint32_t*>(func + 4);
                    if (number < 0x2000) return number;
                }

                // halo's gate: stub is hooked (starts with jmp), scan neighboring stubs
                // ntdll syscall stubs are laid out sequentially, ~32 bytes apart
                // if our target is hooked, find a clean neighbor and calculate by offset
                bool is_hooked = (func[0] == 0xE9) ||  // jmp rel32
                                 (func[0] == 0xFF && func[1] == 0x25) ||  // jmp [rip+disp32]
                                 (func[0] == 0x68 && func[5] == 0xC3);   // push addr; ret

                if (is_hooked) {
                    // scan up and down for clean stubs
                    for (int offset = 1; offset < 500; ++offset) {
                        // try stub above (lower address = lower syscall number)
                        uint8_t* up = func - (offset * 32);
                        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
                            uint32_t neighbor_num = *reinterpret_cast<uint32_t*>(up + 4);
                            uint32_t number = neighbor_num + static_cast<uint32_t>(offset);
                            if (number < 0x2000) return number;
                        }

                        // try stub below (higher address = higher syscall number)
                        uint8_t* down = func + (offset * 32);
                        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
                            uint32_t neighbor_num = *reinterpret_cast<uint32_t*>(down + 4);
                            if (neighbor_num >= static_cast<uint32_t>(offset)) {
                                uint32_t number = neighbor_num - static_cast<uint32_t>(offset);
                                if (number < 0x2000) return number;
                            }
                        }
                    }
                }

                // legacy pattern: mov eax, <number> (older windows, wow64)
                if (func[0] == 0xB8) {
                    uint32_t number = *reinterpret_cast<uint32_t*>(func + 1);
                    if (number < 0x2000) return number;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return SYSCALL_ERROR;
            }
#endif
            return SYSCALL_ERROR;
        }

        template<uint32_t FuncHash>
        CW_FORCEINLINE uint32_t getCachedSyscallNumber() {
            static uint32_t cached = SYSCALL_ERROR;
            if (cached == SYSCALL_ERROR) {
                cached = getSyscallNumber(FuncHash);
            }
            return cached;
        }

#if defined(_WIN64) && !CW_KERNEL_MODE
        // find a "syscall; ret" gadget (0F 05 C3) in ntdll .text section
        CW_FORCEINLINE void* findSyscallGadget() {
            __try {
                void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                if (!ntdll) return nullptr;

                IMAGE_NT_HEADERS* nt = nullptr;
                uint32_t image_size = 0;
                if (!imports::detail::validate_pe_header(ntdll, &nt, &image_size)) return nullptr;

                auto base = reinterpret_cast<uint8_t*>(ntdll);

                auto section = IMAGE_FIRST_SECTION(nt);
                for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
                    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

                    uint32_t sec_start = section->VirtualAddress;
                    uint32_t sec_size = section->Misc.VirtualSize;
                    if (!imports::detail::rva_in_bounds(sec_start, sec_size, image_size)) continue;

                    // scan for syscall; ret (0F 05 C3)
                    for (uint32_t j = 0; j + 2 < sec_size; ++j) {
                        uint8_t* p = base + sec_start + j;
                        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
                            return p;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
            return nullptr;
        }

        CW_FORCEINLINE void* getCachedSyscallGadget() {
            static void* gadget = nullptr;
            if (!gadget) gadget = findSyscallGadget();
            return gadget;
        }

        // indirect syscall invocation via intrinsics
        // sets up registers and jumps to syscall;ret gadget in ntdll
        // return address on stack will point to ntdll, not our module
        template<typename... Args>
        CW_NOINLINE NTSTATUS invokeSyscall(uint32_t number, Args... args) {
            void* gadget = getCachedSyscallGadget();
            if (!gadget || number == SYSCALL_ERROR) return static_cast<NTSTATUS>(0xC0000001);  // STATUS_UNSUCCESSFUL

            // we can't do inline asm in msvc x64, so use a function pointer cast
            // the syscall calling convention: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4
            // eax=syscall number, r10=rcx (first arg copy)
            // we set up a function pointer to the gadget and call through it
            // the OS syscall dispatcher reads eax for the number

            // for indirect syscall we need: mov r10, rcx; mov eax, number; jmp gadget
            // since we can't inline asm, we use a shellcode thunk allocated once
            static thread_local uint8_t thunk[32] = {};
            static thread_local bool thunk_init = false;

            if (!thunk_init) {
                // build: mov r10, rcx (4C 8B D1)
                //        mov eax, imm32 (B8 XX XX XX XX)
                //        jmp [rip+0] (FF 25 00 00 00 00) + 8-byte address
                thunk[0] = 0x4C; thunk[1] = 0x8B; thunk[2] = 0xD1;  // mov r10, rcx
                thunk[3] = 0xB8;  // mov eax, imm32
                // imm32 filled below
                thunk[8] = 0xFF; thunk[9] = 0x25; thunk[10] = 0x00; thunk[11] = 0x00;
                thunk[12] = 0x00; thunk[13] = 0x00;  // jmp [rip+0]
                // 8-byte gadget address at offset 14
                DWORD old_protect;
                VirtualProtect(thunk, sizeof(thunk), PAGE_EXECUTE_READWRITE, &old_protect);
                thunk_init = true;
            }

            *reinterpret_cast<uint32_t*>(thunk + 4) = number;
            *reinterpret_cast<uint64_t*>(thunk + 14) = reinterpret_cast<uint64_t>(gadget);
            CW_COMPILER_BARRIER();

            using SyscallFn = NTSTATUS(__stdcall*)(Args...);
            auto fn = reinterpret_cast<SyscallFn>(static_cast<void*>(thunk));
            return fn(args...);
        }
#endif
    }

    #define CW_SYSCALL_NUMBER(func) (cloakwork::syscall::getCachedSyscallNumber<CW_HASH(#func)>())

#if defined(_WIN64) && !CW_KERNEL_MODE
    #define CW_SYSCALL(func, ...) \
        cloakwork::syscall::invokeSyscall( \
            cloakwork::syscall::getCachedSyscallNumber<CW_HASH(#func)>(), \
            __VA_ARGS__)
#else
    #define CW_SYSCALL(func, ...) func(__VA_ARGS__)
#endif

#else
    namespace syscall {
        static constexpr uint32_t SYSCALL_ERROR = UINT32_MAX;
        inline uint32_t getSyscallNumber(uint32_t) { return SYSCALL_ERROR; }
    }
    #define CW_SYSCALL_NUMBER(func) (cloakwork::syscall::SYSCALL_ERROR)
    #define CW_SYSCALL(func, ...) func(__VA_ARGS__)
#endif

#if CW_ENABLE_VALUE_OBFUSCATION
    namespace comparison {

        template<typename T>
        CW_FORCEINLINE bool obfuscated_equals(T a, T b) {
            if constexpr (std::is_integral_v<T>) {
                // (a == b) <=> ((a ^ b) == 0)
                T diff = a ^ b;
                // use MBA to check if zero
                T zero_check = mba::sub_mba(diff, diff);
                CW_COMPILER_BARRIER();
                return zero_check == static_cast<T>(0) && diff == static_cast<T>(0);
            } else {
                return a == b;
            }
        }

        template<typename T>
        CW_FORCEINLINE bool obfuscated_not_equals(T a, T b) {
            if constexpr (std::is_integral_v<T>) {
                T diff = a ^ b;
                CW_COMPILER_BARRIER();
                return diff != static_cast<T>(0);
            } else {
                return a != b;
            }
        }

        template<typename T>
        CW_FORCEINLINE bool obfuscated_less(T a, T b) {
            if constexpr (std::is_integral_v<T> && std::is_signed_v<T>) {
                // use subtraction and check sign bit
                T diff = mba::sub_mba(a, b);
                CW_COMPILER_BARRIER();
                return diff < 0;
            } else if constexpr (std::is_integral_v<T>) {
                // unsigned comparison via subtraction with overflow check
                CW_COMPILER_BARRIER();
                return a < b;  // fall back for unsigned
            } else {
                return a < b;
            }
        }

        template<typename T>
        CW_FORCEINLINE bool obfuscated_greater(T a, T b) {
            return obfuscated_less(b, a);
        }

        template<typename T>
        CW_FORCEINLINE bool obfuscated_less_equal(T a, T b) {
            return !obfuscated_greater(a, b);
        }

        template<typename T>
        CW_FORCEINLINE bool obfuscated_greater_equal(T a, T b) {
            return !obfuscated_less(a, b);
        }
    }

    #define CW_EQ(a, b) (cloakwork::comparison::obfuscated_equals((a), (b)))
    #define CW_NE(a, b) (cloakwork::comparison::obfuscated_not_equals((a), (b)))
    #define CW_LT(a, b) (cloakwork::comparison::obfuscated_less((a), (b)))
    #define CW_GT(a, b) (cloakwork::comparison::obfuscated_greater((a), (b)))
    #define CW_LE(a, b) (cloakwork::comparison::obfuscated_less_equal((a), (b)))
    #define CW_GE(a, b) (cloakwork::comparison::obfuscated_greater_equal((a), (b)))
#else
    #define CW_EQ(a, b) ((a) == (b))
    #define CW_NE(a, b) ((a) != (b))
    #define CW_LT(a, b) ((a) < (b))
    #define CW_GT(a, b) ((a) > (b))
    #define CW_LE(a, b) ((a) <= (b))
    #define CW_GE(a, b) ((a) >= (b))
#endif

    namespace constants {

        template<typename T, T Value, uint8_t Key = static_cast<uint8_t>(CW_RAND_CT(1, 255))>
        struct encrypted_constant {
            // store encrypted value as a non-constexpr static to prevent the compiler
            // from seeing both the encrypted value and key in the same compile-time context,
            // which would let LTCG constant-fold the XOR back to the original value
            static inline volatile T stored_encrypted = Value ^ static_cast<T>(Key);

            static CW_NOINLINE T get() {
                CW_COMPILER_BARRIER();
                if constexpr (std::is_integral_v<T>) {
                    volatile T enc = stored_encrypted;
                    CW_COMPILER_BARRIER();
                    T out = enc ^ static_cast<T>(Key);
                    CW_COMPILER_BARRIER();
                    return out;
                } else {
                    return Value;
                }
            }
        };

        // runtime-keyed constant (different each execution)
        template<typename T>
        class runtime_constant {
        private:
            T encrypted;
            T key;

        public:
            runtime_constant(T value) {
                key = static_cast<T>(CW_RANDOM_RT());
                if constexpr (std::is_integral_v<T>) {
                    encrypted = value ^ key;
                } else {
                    encrypted = value;
                }
            }

            CW_FORCEINLINE T get() const {
                if constexpr (std::is_integral_v<T>) {
                    volatile T temp = encrypted;
                    CW_COMPILER_BARRIER();
                    return temp ^ key;
                } else {
                    return encrypted;
                }
            }

            CW_FORCEINLINE operator T() const { return get(); }
        };
    }

    #define CW_CONST(val) \
        (cloakwork::constants::encrypted_constant<decltype(val), val>::get())

#if CW_ENABLE_CONTROL_FLOW
    namespace junk {

        template<int N = CW_RAND_CT(1, 1000)>
        CW_NOINLINE void junk_computation() {
            volatile int x = N;
            volatile int y = N * 2;
            CW_COMPILER_BARRIER();

            x = x ^ y;
            y = y + x;
            x = x - y;
            y = ~y;
            x = x & y;

            CW_COMPILER_BARRIER();

            if (control_flow::opaque_false<N>()) {
                volatile int z = x * y;
                z = z >> 3;
                x = z ^ y;
            }
        }

        template<int N = CW_RAND_CT(1, 1000)>
        CW_NOINLINE void junk_control_flow() {
            volatile int state = N % 5;
            CW_COMPILER_BARRIER();

            for (int i = 0; i < 3; ++i) {
                switch (state) {
                    case 0:
                        state = (state + 1) % 5;
                        break;
                    case 1:
                        state = (state * 2) % 5;
                        break;
                    case 2:
                        state = (state - 1 + 5) % 5;
                        break;
                    default:
                        state = 0;
                        break;
                }
                CW_COMPILER_BARRIER();
            }
        }
    }

    #define CW_JUNK() \
        do { \
            cloakwork::junk::junk_computation<CW_RAND_CT(1, 1000)>(); \
        } while(0)

    #define CW_JUNK_FLOW() \
        do { \
            cloakwork::junk::junk_control_flow<CW_RAND_CT(1, 1000)>(); \
        } while(0)
#else
    #define CW_JUNK() ((void)0)
    #define CW_JUNK_FLOW() ((void)0)
#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION
    namespace spoof {

        // find a "ret" (0xC3) gadget in ntdll's executable section
        CW_FORCEINLINE void* findRetGadget() {
#if defined(_WIN32) && !CW_KERNEL_MODE
            __try {
                void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                if (!ntdll) return nullptr;

                IMAGE_NT_HEADERS* nt = nullptr;
                uint32_t image_size = 0;
                if (!imports::detail::validate_pe_header(ntdll, &nt, &image_size)) return nullptr;

                auto base = reinterpret_cast<uint8_t*>(ntdll);

                auto section = IMAGE_FIRST_SECTION(nt);
                for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
                    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

                    uint32_t sec_start = section->VirtualAddress;
                    uint32_t sec_size = section->Misc.VirtualSize;
                    if (!imports::detail::rva_in_bounds(sec_start, sec_size, image_size)) continue;

                    for (uint32_t j = 0; j < sec_size; ++j) {
                        if (base[sec_start + j] == 0xC3) {
                            return base + sec_start + j;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
#endif
            return nullptr;
        }

        CW_FORCEINLINE void* getRetGadget() {
            static void* gadget = nullptr;
            if (!gadget) gadget = findRetGadget();
            return gadget;
        }

        // return address spoofing using _AddressOfReturnAddress intrinsic
        // overwrites our return address with a gadget address (ret in ntdll)
        // so call stacks show ntdll instead of our module
        template<typename Ret, typename... Args>
        class spoofed_call {
        private:
            using FuncPtr = Ret(*)(Args...);
            FuncPtr func;
            void* gadget;

        public:
            spoofed_call(FuncPtr f) : func(f), gadget(getRetGadget()) {}

            CW_NOINLINE Ret operator()(Args... args) {
#if defined(_WIN64)
                if (gadget) {
                    // get pointer to our return address on the stack
                    void** ret_addr_ptr = reinterpret_cast<void**>(_AddressOfReturnAddress());
                    void* real_return = *ret_addr_ptr;

                    // overwrite with gadget (ret instruction in ntdll)
                    // when the callee returns, the stack will show ntdll
                    *ret_addr_ptr = gadget;
                    CW_COMPILER_BARRIER();

                    if constexpr (std::is_void_v<Ret>) {
                        func(args...);
                        // restore real return address
                        *ret_addr_ptr = real_return;
                    } else {
                        Ret result = func(args...);
                        // restore real return address so we can actually return
                        *ret_addr_ptr = real_return;
                        return result;
                    }
                } else
#endif
                {
                    return func(args...);
                }
            }
        };
    }

    #define CW_SPOOF_CALL(func) (cloakwork::spoof::spoofed_call<decltype(func)>{func})
#else
    namespace spoof {
        inline void* findRetGadget() { return nullptr; }
        inline void* getRetGadget() { return nullptr; }
    }
    #define CW_SPOOF_CALL(func) (func)
#endif

#if CW_ENABLE_INTEGRITY_CHECKS
    namespace integrity {

        CW_FORCEINLINE uint32_t computeHash(const void* data, size_t size) {
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            uint32_t hash = 0x811c9dc5;

            for (size_t i = 0; i < size; ++i) {
                hash ^= bytes[i];
                hash *= 0x01000193;
            }

            return hash;
        }

        template<typename Func>
        class integrity_checked {
        private:
            Func* func;
            uint32_t expectedHash;
            size_t codeSize;
            mutable CW_ATOMIC(uint32_t) checkCount{0};

        public:
            integrity_checked(Func* f, size_t size)
                : func(f), codeSize(size) {
                expectedHash = computeHash(reinterpret_cast<const void*>(f), size);
            }

            template<typename... Args>
            CW_FORCEINLINE auto operator()(Args&&... args) {
                if ((++checkCount % 100) == 0) {
                    uint32_t currentHash = computeHash(
                        reinterpret_cast<const void*>(func), codeSize);

                    if (currentHash != expectedHash) {
#if CW_ANTI_DEBUG_RESPONSE == 1
                        __debugbreak();
                        *(volatile int*)0 = 0;
#endif
                    }
                }

                return func(std::forward<Args>(args)...);
            }

            bool verify() const {
                uint32_t currentHash = computeHash(
                    reinterpret_cast<const void*>(func), codeSize);
                return currentHash == expectedHash;
            }
        };

        CW_FORCEINLINE bool detectHook(const void* func) {
#ifdef _WIN32
            const uint8_t* bytes = static_cast<const uint8_t*>(func);

            // check for jmp rel32 (E9 XX XX XX XX)
            if (bytes[0] == 0xE9) return true;

            // check for jmp [rip+disp32] (FF 25 XX XX XX XX)
            if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;

            // check for mov rax, addr; jmp rax (48 B8 XX XX XX XX XX XX XX XX FF E0)
            if (bytes[0] == 0x48 && bytes[1] == 0xB8) return true;

            // check for push addr; ret (68 XX XX XX XX C3)
            if (bytes[0] == 0x68 && bytes[5] == 0xC3) return true;

            // check for int3 breakpoint
            if (bytes[0] == 0xCC) return true;
#endif
            return false;
        }

        template<typename... Funcs>
        CW_FORCEINLINE bool verifyFunctions(Funcs*... funcs) {
            return ((!detectHook(reinterpret_cast<const void*>(funcs))) && ...);
        }
    }

    #define CW_INTEGRITY_CHECK(func, size) \
        (cloakwork::integrity::integrity_checked<decltype(func)>{&func, size})

    #define CW_DETECT_HOOK(func) \
        (cloakwork::integrity::detectHook(reinterpret_cast<const void*>(&func)))
#else
    namespace integrity {
        inline uint32_t computeHash(const void*, size_t) { return 0; }
        inline bool detectHook(const void*) { return false; }
        template<typename... Funcs>
        inline bool verifyFunctions(Funcs*...) { return true; }
    }
    #define CW_INTEGRITY_CHECK(func, size) (&func)
    #define CW_DETECT_HOOK(func) (false)
#endif

    namespace pe_erase {

        // zero DOS header, NT headers, and section table to prevent dumping
        CW_FORCEINLINE bool erase_pe_header() {
#if defined(_WIN32) && !CW_KERNEL_MODE
            __try {
                HMODULE module = GetModuleHandleA(nullptr);
                if (!module) return false;

                auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
                if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) return false;

                auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

                size_t header_size = dos->e_lfanew +
                    sizeof(IMAGE_NT_HEADERS) +
                    (nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

                DWORD old_protect;
                if (!VirtualProtect(module, header_size, PAGE_READWRITE, &old_protect))
                    return false;

                volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(module);
                for (size_t i = 0; i < header_size; ++i)
                    p[i] = 0;

                VirtualProtect(module, header_size, old_protect, &old_protect);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
#elif CW_KERNEL_MODE
            // kernel mode: zero driver PE header via MmGetSystemRoutineAddress
            // requires the driver's base address to be passed in
            return false;  // caller should use erase_driver_header(base)
#else
            return false;
#endif
        }

#if CW_KERNEL_MODE
        // kernel mode: erase a driver's PE header given its base address
        CW_FORCEINLINE bool erase_driver_header(void* driver_base) {
            if (!driver_base || !MmIsAddressValid(driver_base)) return false;

            auto dos = static_cast<IMAGE_DOS_HEADER*>(driver_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) return false;

            auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<uint8_t*>(driver_base) + dos->e_lfanew);
            if (!MmIsAddressValid(nt)) return false;
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

            size_t header_size = dos->e_lfanew +
                sizeof(IMAGE_NT_HEADERS) +
                (nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

            volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(driver_base);
            for (size_t i = 0; i < header_size; ++i)
                p[i] = 0;

            return true;
        }
#endif
    }

#if CW_ENABLE_ANTI_DEBUG && defined(_WIN32) && !CW_KERNEL_MODE
    namespace anti_debug {
        namespace enhanced {

            CW_FORCEINLINE bool check_debug_port() {
                __try {
                    typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
                        HANDLE, ULONG, PVOID, ULONG, PULONG);

                    static NtQueryInformationProcessFn NtQueryInformationProcess = nullptr;
                    static bool resolved = false;

                    if (!resolved) {
                        void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                        if (ntdll) {
                            NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                                imports::getProcAddress(ntdll, CW_HASH("NtQueryInformationProcess")));
                        }
                        resolved = true;
                    }

                    if (!NtQueryInformationProcess) return false;

                    // ProcessDebugPort (0x7) - nonzero if debugger attached
                    ULONG_PTR debug_port = 0;
                    NTSTATUS status = NtQueryInformationProcess(
                        GetCurrentProcess(), 0x7, &debug_port, sizeof(debug_port), nullptr);
                    if (status == 0 && debug_port != 0) return true;

                    // ProcessDebugObjectHandle (0x1E) - handle exists if debugger attached
                    HANDLE debug_object = nullptr;
                    status = NtQueryInformationProcess(
                        GetCurrentProcess(), 0x1E, &debug_object, sizeof(debug_object), nullptr);
                    if (status == 0) return true;  // STATUS_SUCCESS means debug object exists

                    // ProcessDebugFlags (0x1F) - 0 means debugger present
                    ULONG debug_flags = 1;
                    status = NtQueryInformationProcess(
                        GetCurrentProcess(), 0x1F, &debug_flags, sizeof(debug_flags), nullptr);
                    if (status == 0 && debug_flags == 0) return true;

                    return false;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            }

            CW_FORCEINLINE bool hide_from_debugger() {
                __try {
                    typedef NTSTATUS(NTAPI* NtSetInformationThreadFn)(
                        HANDLE, ULONG, PVOID, ULONG);

                    static NtSetInformationThreadFn NtSetInformationThread = nullptr;
                    static bool resolved = false;

                    if (!resolved) {
                        void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                        if (ntdll) {
                            NtSetInformationThread = reinterpret_cast<NtSetInformationThreadFn>(
                                imports::getProcAddress(ntdll, CW_HASH("NtSetInformationThread")));
                        }
                        resolved = true;
                    }

                    if (!NtSetInformationThread) return false;

                    // ThreadHideFromDebugger (0x11)
                    NTSTATUS status = NtSetInformationThread(
                        GetCurrentThread(), 0x11, nullptr, 0);
                    return (status == 0);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            }
        }
    }
#endif

    #if CW_ENABLE_VALUE_OBFUSCATION
        #define CW_INT(x) (cloakwork::obfuscated_value<decltype(x)>{x})
        #define CW_MBA(x) (cloakwork::mba_obfuscated<decltype(x)>{x})

        // obfuscated XOR using MBA: a ^ b = (a | b) - (a & b) ... via MBA transforms
        #define CW_XOR(a, b) (CW_SUB(CW_OR((a), (b)), CW_AND((a), (b))))
    #else
        #define CW_INT(x) (x)
        #define CW_MBA(x) (x)
        #define CW_XOR(a, b) ((a) ^ (b))
    #endif

    #if CW_ENABLE_FUNCTION_OBFUSCATION
        #define CW_CALL(func) cloakwork::obfuscated_call<decltype(func)>{func}
    #else
        #define CW_CALL(func) (func)
    #endif

    #if CW_ENABLE_DATA_HIDING
        #define CW_SCATTER(x) (cloakwork::data_hiding::scattered_value<decltype(x)>{x})
        #define CW_POLY(x) (cloakwork::data_hiding::polymorphic_value<decltype(x)>{x})
    #else
        #define CW_SCATTER(x) (x)
        #define CW_POLY(x) (x)
    #endif

    #if CW_ENABLE_ANTI_DEBUG
        #define CW_CHECK_ANALYSIS() \
            do { \
                if(cloakwork::anti_debug::comprehensive_check()) { \
                    volatile int crash = *(int*)0; \
                } \
            } while(0)
    #else
        #define CW_CHECK_ANALYSIS() ((void)0)
    #endif

    #if CW_ENABLE_CONTROL_FLOW
        #define CW_BRANCH(cond) \
            if(cloakwork::control_flow::indirect_branch(cloakwork::control_flow::opaque_true<>() && (cond)))
    #else
        #define CW_BRANCH(cond) if(cond)
    #endif

    #define CW_ERASE_PE_HEADER() (cloakwork::pe_erase::erase_pe_header())

    // erases debug-related IAT entries (IsDebuggerPresent, strstr, etc.)
    // that leak as signatures even when not used by our code (CRT linkage)

    namespace iat_scrub {

        CW_FORCEINLINE bool scrub_debug_imports() {
#if defined(_WIN32) && !CW_KERNEL_MODE
            __try {
                HMODULE module = GetModuleHandleA(nullptr);
                if (!module) return false;

                auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
                if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x1000) return false;

                auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

                auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (import_dir.VirtualAddress == 0) return false;

                auto base = reinterpret_cast<uint8_t*>(module);
                auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                    base + import_dir.VirtualAddress);

                constexpr uint32_t scrub_hashes[] = {
                    CW_HASH("IsDebuggerPresent"),
                    CW_HASH("CheckRemoteDebuggerPresent"),
                    CW_HASH("OutputDebugStringA"),
                    CW_HASH("OutputDebugStringW"),
                };

                for (; import_desc->Name; ++import_desc) {
                    auto thunk_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                        base + import_desc->OriginalFirstThunk);
                    auto func_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                        base + import_desc->FirstThunk);

                    for (; thunk_ref->u1.AddressOfData; ++thunk_ref, ++func_ref) {
                        if (IMAGE_SNAP_BY_ORDINAL(thunk_ref->u1.Ordinal)) continue;

                        auto import_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            base + thunk_ref->u1.AddressOfData);

                        uint32_t name_hash = hash::fnv1a_runtime(
                            reinterpret_cast<const char*>(import_name->Name));

                        for (auto h : scrub_hashes) {
                            if (name_hash == h) {
                                DWORD old_protect;
                                if (VirtualProtect(&func_ref->u1.Function,
                                    sizeof(func_ref->u1.Function),
                                    PAGE_READWRITE, &old_protect)) {
                                    func_ref->u1.Function = reinterpret_cast<ULONG_PTR>(
                                        static_cast<BOOL(WINAPI*)()>([]() -> BOOL { return FALSE; }));
                                    VirtualProtect(&func_ref->u1.Function,
                                        sizeof(func_ref->u1.Function),
                                        old_protect, &old_protect);
                                }
                                break;
                            }
                        }
                    }
                }
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
#endif
            return false;
        }
    }

    #define CW_SCRUB_DEBUG_IMPORTS() (cloakwork::iat_scrub::scrub_debug_imports())

#if CW_ENABLE_ANTI_DEBUG && defined(_WIN32) && !CW_KERNEL_MODE
    #define CW_HIDE_THREAD() (cloakwork::anti_debug::enhanced::hide_from_debugger())
    #define CW_CHECK_DEBUG_PORT() (cloakwork::anti_debug::enhanced::check_debug_port())
#else
    #define CW_HIDE_THREAD() ((void)0)
    #define CW_CHECK_DEBUG_PORT() (false)
#endif

#if CW_ENABLE_VALUE_OBFUSCATION
    using obf_bool = bool_obfuscation::obfuscated_bool<>;
#else
    using obf_bool = bool_obfuscation::obfuscated_bool;
#endif

#if CW_ENABLE_METAMORPHIC
    template<typename Sig>
    using meta_func = metamorphic::metamorphic_function<Sig>;
#else
    template<typename Sig>
    using meta_func = metamorphic::metamorphic_function<Sig>;
#endif

    template<typename T>
    using rt_const = constants::runtime_constant<T>;

#if CW_ENABLE_ANTI_DEBUG
    #define CW_IS_DEBUGGED()             (cloakwork::anti_debug::is_debugger_present())
    #define CW_HAS_HWBP()               (cloakwork::anti_debug::has_hardware_breakpoints())
    #define CW_CHECK_DEBUG()             (cloakwork::anti_debug::comprehensive_check())
    #define CW_DETECT_HIDING()           (cloakwork::anti_debug::advanced::detect_hiding_tools())
    #define CW_DETECT_PARENT()           (cloakwork::anti_debug::advanced::suspicious_parent_process())
    #define CW_DETECT_KERNEL_DBG()       (cloakwork::anti_debug::advanced::kernel_debugger_present())
    #define CW_TIMING_CHECK()            (cloakwork::anti_debug::advanced::advanced_timing_check())
    #define CW_DETECT_DBG_ARTIFACTS()    (cloakwork::anti_debug::advanced::detect_debugger_artifacts())
#else
    #define CW_IS_DEBUGGED()             (false)
    #define CW_HAS_HWBP()               (false)
    #define CW_CHECK_DEBUG()             (false)
    #define CW_DETECT_HIDING()           (false)
    #define CW_DETECT_PARENT()           (false)
    #define CW_DETECT_KERNEL_DBG()       (false)
    #define CW_TIMING_CHECK()            (false)
    #define CW_DETECT_DBG_ARTIFACTS()    (false)
#endif

#if CW_ENABLE_ANTI_VM
    #define CW_DETECT_HYPERVISOR()       (cloakwork::anti_debug::anti_vm::is_hypervisor_present())
    #define CW_DETECT_VM_VENDOR()        (cloakwork::anti_debug::anti_vm::detect_vm_vendor())
    #define CW_DETECT_LOW_RESOURCES()    (cloakwork::anti_debug::anti_vm::detect_low_resources())
    #define CW_DETECT_SANDBOX_DLLS()     (cloakwork::anti_debug::anti_vm::detect_sandbox_dlls())
#else
    #define CW_DETECT_HYPERVISOR()       (false)
    #define CW_DETECT_VM_VENDOR()        (false)
    #define CW_DETECT_LOW_RESOURCES()    (false)
    #define CW_DETECT_SANDBOX_DLLS()     (false)
#endif

#if CW_ENABLE_IMPORT_HIDING
    #define CW_GET_MODULE(name)          (cloakwork::imports::getModuleBase(CW_HASH_CI(name)))
    #define CW_GET_PROC(mod, func)       (cloakwork::imports::getProcAddress(mod, CW_HASH(func)))
#endif

    #define CW_HASH_RT(str)              (cloakwork::hash::fnv1a_runtime(str))
    #define CW_HASH_RT_CI(str)           (cloakwork::hash::fnv1a_runtime_ci(str))

#if CW_ENABLE_INTEGRITY_CHECKS
    #define CW_COMPUTE_HASH(ptr, size)   (cloakwork::integrity::computeHash(ptr, size))
    #define CW_VERIFY_FUNCS(...)         (cloakwork::integrity::verifyFunctions(__VA_ARGS__))
#endif

    #define CW_RET_GADGET()              (cloakwork::spoof::getRetGadget())

    // MBA negation (completes CW_ADD / CW_SUB / CW_AND / CW_OR set)
#if CW_ENABLE_VALUE_OBFUSCATION
    #define CW_NEG(a)                    (cloakwork::mba::neg_mba(a))
#else
    #define CW_NEG(a)                    (-(a))
#endif

} // namespace cloakwork

#ifdef _MSC_VER
    #pragma warning(pop)
#endif

#endif // CLOAKWORK_H
