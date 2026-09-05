#ifndef CLOAKWORK_H
#define CLOAKWORK_H

// Cloakwork advanced obfuscation library - header-only c++20 implementation
// Source-level obfuscation helpers; see README.md for limits and supported builds.

// ██████╗██╗      ██████╗  █████╗ ██╗  ██╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
//██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
//██║     ██║     ██║   ██║███████║█████╔╝ ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
//██║     ██║     ██║   ██║██╔══██║██╔═██╗ ██║███╗██║██║   ██║██╔══██╗██╔═██╗
//╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
// ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

// Created by @ck0i on Discord.
// Inspiration from obfusheader.h, Zapcrash's nimrodhide.h, and qengine.

/*++

Refer to the README.md for usage.

--*/

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

#ifndef CW_BUILD_SEED
    #define CW_BUILD_SEED 0xC10A2026u
#endif

// Stable within this header, independent of the includer's counter state.
#define CW_DETAIL_RANDOM_CT() (static_cast<uint32_t>(CW_BUILD_SEED) ^ (static_cast<uint32_t>(__LINE__) * 0x9E3779B9u))
#define CW_DETAIL_RAND_CT(min, max) ((min) + (CW_DETAIL_RANDOM_CT() % ((max) - (min) + 1)))

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

#if CW_ENABLE_VALUE_OBFUSCATION && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_VALUE_OBFUSCATION requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_ANTI_DEBUG && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_ANTI_DEBUG requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_STRING_ENCRYPTION && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_STRING_ENCRYPTION requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_FUNCTION_OBFUSCATION requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION && !CW_ENABLE_STRING_ENCRYPTION
    #error "CW_ENABLE_FUNCTION_OBFUSCATION requires CW_ENABLE_STRING_ENCRYPTION to be enabled"
#endif

#if CW_ENABLE_METAMORPHIC && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_METAMORPHIC requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_IMPORT_HIDING && !CW_ENABLE_COMPILE_TIME_RANDOM
    #error "CW_ENABLE_IMPORT_HIDING requires CW_ENABLE_COMPILE_TIME_RANDOM to be enabled"
#endif

#if CW_ENABLE_SYSCALLS && !CW_ENABLE_IMPORT_HIDING
    #error "CW_ENABLE_SYSCALLS requires CW_ENABLE_IMPORT_HIDING to be enabled"
#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION && !CW_ENABLE_IMPORT_HIDING
    #error "CW_ENABLE_FUNCTION_OBFUSCATION requires CW_ENABLE_IMPORT_HIDING to be enabled"
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
    #define CW_MO_ACQUIRE 0
    #define CW_MO_RELEASE 0

#else
    #include <array>
    #include <cstdint>
    #include <functional>
    #include <stdexcept>
    #include <limits>
    #include <span>
    #include <vector>
    #include <algorithm>
    #include <atomic>
    #include <mutex>
    #include <memory>
    #include <bit>
    #include <type_traits>
    #include <utility>
    #include <cstring>
    #include <cstdlib>
    #include <ctime>

    #ifdef _WIN32
        #include <windows.h>
        #include <intrin.h>
        #include <winternl.h>
        #include <tlhelp32.h>
        #include <iphlpapi.h>
        #pragma comment(lib, "iphlpapi.lib")
        #pragma comment(lib, "advapi32.lib")

        // Full LDR_DATA_TABLE_ENTRY shape; winternl.h exposes a truncated view.
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
                    } HashLinksData;
                };
                union {
                    ULONG TimeDateStamp;
                    PVOID LoadedImports;
                };
                PVOID EntryPointActivationContext;
                PVOID PatchInformation;
            };
        }
    #else
        #include <cstdint>
        #include <cpuid.h>
    #endif

    #define CW_ATOMIC(T) std::atomic<T>
    #define CW_MUTEX std::mutex
    #define CW_LOCK_GUARD(m) std::lock_guard<std::mutex> _cw_guard(m)
    #define CW_MO_RELAXED std::memory_order_relaxed
    #define CW_MO_ACQUIRE std::memory_order_acquire
    #define CW_MO_RELEASE std::memory_order_release

#endif // CW_KERNEL_MODE

#ifdef _MSC_VER
    #define CW_FORCEINLINE __forceinline
    #define CW_NOINLINE __declspec(noinline)
    #define CW_SECTION(x) __declspec(allocate(x))
    #define CW_COMPILER_BARRIER() _ReadWriteBarrier()
    // Optimization controls for supported compiler paths.
    #define CW_OPT_OFF __pragma(optimize("", off))
    #define CW_OPT_ON __pragma(optimize("", on))
    #pragma warning(push)
    #pragma warning(disable: 4996 4244 4267 4201 4189 4702)
    #define CW_RDSEED
#elif defined(__GNUC__) || defined(__clang__)

    #define CW_FORCEINLINE __attribute__((always_inline)) inline
    #define CW_NOINLINE __attribute__((noinline))
    #define CW_SECTION(x) __attribute__((section(x)))
    #define CW_COMPILER_BARRIER() asm volatile("" ::: "memory")
    #define CW_OPT_OFF _Pragma("GCC push_options") _Pragma("GCC optimize(\"O0\")")
    #define CW_OPT_ON _Pragma("GCC pop_options")
    #define CW_RDSEED __attribute__((target("rdseed")))
#else
    #define CW_FORCEINLINE inline
    #define CW_NOINLINE
    #define CW_SECTION(x)
    #define CW_COMPILER_BARRIER() std::atomic_signal_fence(std::memory_order_seq_cst)
    #define CW_OPT_OFF
    #define CW_OPT_ON
    #define CW_RDSEED
#endif

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-volatile"
    #pragma clang diagnostic ignored "-Wunused-variable"
    #pragma clang diagnostic ignored "-Wmissing-field-initializers"
    #pragma clang diagnostic ignored "-Wbitwise-instead-of-logical"
#endif

// Public API, lifetime contracts, and examples are documented in README.md.

namespace cloakwork {

#if !CW_KERNEL_MODE
    template<typename T>
    concept Integral = std::is_integral_v<T>;
    template<typename T>
    concept Arithmetic = std::is_arithmetic_v<T>;
#endif

    namespace detail {
#if !CW_KERNEL_MODE
        inline void wipe(void* data, size_t size) noexcept {
            auto bytes = static_cast<volatile uint8_t*>(data);
            for (size_t i = 0; i < size; ++i) bytes[i] = 0;
            CW_COMPILER_BARRIER();
        }
#endif
        template<typename T>
        using clean_value_t = std::remove_cv_t<std::remove_reference_t<T>>;

#if !CW_KERNEL_MODE
        template<typename A, typename B>
        constexpr auto range_from_sample(A low, B high, uint64_t sample) {
            static_assert(std::is_integral_v<A> && std::is_integral_v<B>, "Random bounds must be integers");
            using R = decltype(low + high);
            using U = std::make_unsigned_t<R>;
            const R first = static_cast<R>(low), last = static_cast<R>(high);
            if (first > last) throw std::invalid_argument("Cloakwork random bounds are reversed");
            const U span = static_cast<U>(static_cast<U>(last) - static_cast<U>(first) + U{1});
            const U offset = span == 0 ? static_cast<U>(sample) : static_cast<U>(sample % span);
            return std::bit_cast<R>(static_cast<U>(static_cast<U>(first) + offset));
        }
#endif

        template<typename T>
        inline constexpr size_t default_scatter_chunks_v =
            (sizeof(clean_value_t<T>) >= 8) ? 8 :
            ((sizeof(clean_value_t<T>) >= 2) ? sizeof(clean_value_t<T>) : 2);
    }

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
#if defined(__clang__)
            (void)out;
            return false;
#elif defined(_MSC_VER)
            static bool has_rdseed = [] {
                int cpuInfo[4];
                __cpuidex(cpuInfo, 7, 0);
                return (cpuInfo[1] & (1 << 18)) != 0;
            }();

            if (!has_rdseed) return false;
#if defined(_M_X64) || defined(_M_ARM64EC)
            return _rdseed64_step(reinterpret_cast<unsigned long long*>(&out)) != 0;
#elif defined(_M_IX86)
            unsigned int lo = 0, hi = 0;
            if (_rdseed32_step(&lo) == 0) return false;
            if (_rdseed32_step(&hi) == 0) return false;
            out = (static_cast<uint64_t>(hi) << 32) | lo;
            return true;
#else
            return false;
#endif

#else
            (void)out;
            return false;
#endif
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
            thread_local uint64_t state = [] {
                const uint64_t seed = runtime_entropy_seed();
                return seed ? seed : 0x9E3779B97F4A7C15ULL;
            }();
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
        constexpr uint32_t mix_compile_seed(uint32_t seed) {
            seed ^= seed >> 16;
            seed *= 0x7feb352dU;
            seed ^= seed >> 15;
            seed *= 0x846ca68bU;
            seed ^= seed >> 16;
            return seed;
        }

        constexpr uint32_t compile_seed_impl(uint32_t line, uint32_t counter) {
            uint32_t seed = 0xDEADBEEF;
            seed ^= line * 0x01000193;
            seed ^= counter * 0x811c9dc5;
            seed *= 0x1664525;
            seed += 0x1013904223;
            return mix_compile_seed(seed);
        }
#else
        consteval uint32_t mix_compile_seed(uint32_t seed) {
            seed ^= seed >> 16;
            seed *= 0x7feb352dU;
            seed ^= seed >> 15;
            seed *= 0x846ca68bU;
            seed ^= seed >> 16;
            return seed;
        }

        template<size_t FileN>
        consteval uint32_t compile_seed_impl(const char (&file)[FileN], uint32_t line, uint32_t counter) {
            constexpr uint32_t build_seed = static_cast<uint32_t>(CW_BUILD_SEED);
            uint32_t file_hash = fnv1a_hash(file);
            uint32_t seed = build_seed ^ (file_hash >> 1);
            seed ^= line * 0x01000193u;
            seed ^= counter * 0x9E3779B9u;
            return mix_compile_seed(seed);
        }
#endif
    }

    // MSVC 19.50 rejects the original random_generator<...> path in anti-debug
    // callsites when Edit-and-Continue debug rewriting materializes __LINE__ as a
    // non-constant symbol. Materialize the entropy directly to keep the result
    // constexpr while preserving per-expansion variation through __COUNTER__.
#if CW_KERNEL_MODE
    #define CW_COMPILE_SEED() (cloakwork::detail::compile_seed_impl(__LINE__, __COUNTER__))
#else
    #define CW_COMPILE_SEED() (cloakwork::detail::compile_seed_impl(__FILE__, __LINE__, __COUNTER__))
#endif
    #define CW_RANDOM_CT() (CW_COMPILE_SEED())
    #define CW_RAND_CT(min, max) ((min) + (CW_RANDOM_CT() % ((max) - (min) + 1)))

    #define CW_RANDOM_RT() (cloakwork::detail::runtime_entropy())
    #define CW_RAND_RT(min, max) ((min) + (CW_RANDOM_RT() % ((max) - (min) + 1)))
#else
    #define CW_RANDOM_CT() (static_cast<uint32_t>(CW_BUILD_SEED) ^ (static_cast<uint32_t>(__LINE__) * 0x9E3779B9u) ^ static_cast<uint32_t>(__COUNTER__))
    #define CW_RAND_CT(min, max) ((min) + (CW_RANDOM_CT() % ((max) - (min) + 1)))
    #define CW_RANDOM_RT() (rand())
    #define CW_RAND_RT(min, max) ((min) + (rand() % ((max) - (min) + 1)))
#endif

#if !CW_KERNEL_MODE
    #undef CW_RAND_CT
    #undef CW_RAND_RT
    #define CW_RAND_CT(min, max) (cloakwork::detail::range_from_sample((min), (max), \
        (static_cast<uint64_t>(CW_RANDOM_CT()) << 32) | CW_RANDOM_CT()))
    #define CW_RAND_RT(min, max) (cloakwork::detail::range_from_sample((min), (max), CW_RANDOM_RT()))
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

        consteval uint32_t fnv1a_wide_ci_ascii(const wchar_t* str, size_t len) {
            uint32_t hash = 0x811c9dc5;
            for (size_t i = 0; i < len; ++i) {
                wchar_t c = str[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                hash ^= static_cast<uint8_t>(c & 0xFF);
                hash *= 0x01000193;
            }
            return hash;
        }

        template<size_t N>
        consteval uint32_t fnv1a_wide_ci_ascii(const wchar_t (&str)[N]) {
            return fnv1a_wide_ci_ascii(str, N - 1);
        }
    }

    #define CW_HASH(s) ([]() consteval { return cloakwork::hash::fnv1a(s); }())
    #define CW_HASH_WIDE(s) ([]() consteval { return cloakwork::hash::fnv1a_wide(s); }())
    #define CW_HASH_CI(s) ([]() consteval { return cloakwork::hash::fnv1a_ci(s); }())
    #define CW_HASH_WIDE_CI(s) ([]() consteval { return cloakwork::hash::fnv1a_wide_ci_ascii(s); }())

    namespace internal_cipher {

        //
        // position-dependent xor cipher to prevent Hex-Rays stack-string reconstruction.
        // mix constants are derived from the Key so each stub has unique imul operands
        // and shift widths — prevents pattern scanning for fixed magic values.
        //
        template<uint32_t Key>
        struct cipher_params {
            static constexpr uint32_t mix_a = 0x9E3779B9u ^ (Key * 0x01000193u);
            static constexpr uint32_t mix_b = 0x45D9F3Bu ^ ((Key >> 7) * 0x27D4EB2Du);
            static constexpr uint32_t shift_a = 13u + (Key & 3u);
            static constexpr uint32_t shift_b = 11u + ((Key >> 2) & 3u);
            static constexpr bool extra_round = (Key & 0x10u) != 0;
        };

        template<uint32_t Key, size_t N>
        struct encrypted_buf {
            uint8_t data[N];

            consteval encrypted_buf(const char (&str)[N]) : data{} {
                using P = cipher_params<Key>;
                for (size_t i = 0; i < N; ++i) {
                    uint32_t subkey = Key ^ (static_cast<uint32_t>(i) * P::mix_a);
                    subkey ^= subkey >> P::shift_a;
                    subkey *= P::mix_b;
                    subkey ^= subkey >> P::shift_b;
                    if constexpr (P::extra_round) {
                        subkey ^= subkey >> 7;
                        subkey *= 0x119DE1F3u ^ (Key >> 16);
                    }
                    data[i] = static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(subkey);
                }
            }
        };

        template<uint32_t Key, size_t N>
        CW_NOINLINE void decrypt_to_stack(const encrypted_buf<Key, N>& enc, char (&out)[N]) {
            using P = cipher_params<Key>;
            volatile uint8_t* dst = reinterpret_cast<volatile uint8_t*>(out);
            for (size_t i = 0; i < N; ++i) {
                uint32_t subkey = Key ^ (static_cast<uint32_t>(i) * P::mix_a);
                subkey ^= subkey >> P::shift_a;
                subkey *= P::mix_b;
                subkey ^= subkey >> P::shift_b;
                if constexpr (P::extra_round) {
                    subkey ^= subkey >> 7;
                    subkey *= 0x119DE1F3u ^ (Key >> 16);
                }
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
            (CW_HASH(str) ^ CW_DETAIL_RANDOM_CT()), sizeof(str)> \
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

            CW_FORCEINLINE void* get_proc_by_hash(void* module, uint32_t func_hash);

            CW_FORCEINLINE void* resolve_forwarded_export(const char* forward_str, size_t max_len) {
#if defined(_WIN32) && !CW_KERNEL_MODE
                if (!forward_str || max_len == 0) return nullptr;

                size_t dot_pos = max_len;
                size_t end_pos = max_len;
                for (size_t i = 0; i < max_len; ++i) {
                    char c = forward_str[i];
                    if (c == '.' && dot_pos == max_len) dot_pos = i;
                    if (c == '\0') {
                        end_pos = i;
                        break;
                    }
                }

                if (dot_pos == max_len || end_pos == max_len || dot_pos == 0 || dot_pos + 1 >= end_pos)
                    return nullptr;

                char module_name[256];
                if (dot_pos >= sizeof(module_name) - 5) return nullptr;

                for (size_t i = 0; i < dot_pos; ++i)
                    module_name[i] = forward_str[i];
                module_name[dot_pos] = '.';
                module_name[dot_pos + 1] = 'd';
                module_name[dot_pos + 2] = 'l';
                module_name[dot_pos + 3] = 'l';
                module_name[dot_pos + 4] = '\0';

                void* target_mod = get_module_by_hash(hash::fnv1a_runtime_ci(module_name));
                if (!target_mod) return nullptr;

                return get_proc_by_hash(target_mod, hash::fnv1a_runtime(forward_str + dot_pos + 1));
#else
                (void)forward_str;
                (void)max_len;
                return nullptr;
#endif
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
                            uint32_t func_rva = functions[ordinal];
                            if (!func_rva || func_rva >= image_size) return nullptr;

                            uint64_t export_start = static_cast<uint64_t>(exp_dir.VirtualAddress);
                            uint64_t export_end = export_start + static_cast<uint64_t>(exp_dir.Size);
                            if (static_cast<uint64_t>(func_rva) >= export_start &&
                                static_cast<uint64_t>(func_rva) < export_end) {
                                return resolve_forwarded_export(
                                    reinterpret_cast<const char*>(base + func_rva),
                                    static_cast<size_t>(export_end - func_rva));
                            }

                            return base + func_rva;
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
            // scan for int3 software breakpoints
            for (size_t i = 0; i < size; ++i) {
                if (bytes[i] == 0xCC) return true;
            }
            // check function prologue for common inline hook signatures
            if (size >= 5 && bytes[0] == 0xE9) return true;                // jmp rel32
            if (size >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25)
                return true;                                               // jmp [rip+disp32]
            if (size >= 2 && bytes[0] == 0xEB) return true;                // jmp rel8 (short)
#ifdef _WIN64
            if (size >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8)
                return true;                                               // mov rax, imm64
            if (size >= 14 && bytes[0] == 0xFF && bytes[1] == 0x25 &&
                bytes[2] == 0x00 && bytes[3] == 0x00 && bytes[4] == 0x00 && bytes[5] == 0x00)
                return true;                                               // jmp [rip+0] (14-byte hook)
#endif
            if (size >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3)
                return true;                                               // push imm32; ret
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
            unsigned long dr0_val = 0, dr1_val = 0, dr2_val = 0, dr3_val = 0;
            __asm {
                mov eax, dr0
                mov dr0_val, eax
                mov eax, dr1
                mov dr1_val, eax
                mov eax, dr2
                mov dr2_val, eax
                mov eax, dr3
                mov dr3_val, eax
            }
            return (dr0_val || dr1_val || dr2_val || dr3_val);
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
                    if (pEnumWindows && pGetClassNameA) {
                        constexpr uint32_t dbg_class_hashes[] = {
                            CW_HASH("OLLYDBG"),
                            CW_HASH("WinDbgFrameClass"),
                            CW_HASH("ID"),
                            CW_HASH("ObsidianGUI"),
                        };
                        struct enum_ctx {
                            bool found;
                            const uint32_t* class_hashes;
                            size_t class_count;
                            decltype(pGetClassNameA) getClassName;
                        };

                        enum_ctx ctx = {
                            false, dbg_class_hashes, sizeof(dbg_class_hashes)/sizeof(uint32_t),
                            pGetClassNameA
                        };

                        pEnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                            auto* c = reinterpret_cast<enum_ctx*>(lParam);
                            char buf[256];
                            if (c->getClassName(hwnd, buf, sizeof(buf))) {
                                uint32_t h = hash::fnv1a_runtime(buf);
                                for (size_t i = 0; i < c->class_count; ++i)
                                    if (h == c->class_hashes[i]) { c->found = true; return FALSE; }
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
                        struct { BOOLEAN KernelDebuggerEnabled; BOOLEAN KernelDebuggerNotPresent; } kdi = {};
                        // SystemKernelDebuggerInformation = 0x23
                        NTSTATUS status = NtQuerySystemInformation(0x23, &kdi, sizeof(kdi), nullptr);
                        if (status == 0 && kdi.KernelDebuggerEnabled && !kdi.KernelDebuggerNotPresent) return true;
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
                            CW_HASH_CI("x86dbg.exe"),
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
                    //
                    // Self-calibrating timing check. First invocation records a
                    // baseline measurement with no debugger. Subsequent calls
                    // compare against a multiple of that baseline. This makes
                    // the threshold unpatchable since it's derived at runtime.
                    //
                    static volatile uint64_t baseline_tsc = 0;

                    LARGE_INTEGER freq, qpc_start, qpc_end;
                    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0)
                        return false;

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

                    if (baseline_tsc == 0) {
                        // first calibration run -- store baseline, don't flag
                        baseline_tsc = tsc_delta;
                        return false;
                    }

                    // suspicious if > 10x baseline; keep this generous to tolerate scheduler noise
                    if (tsc_delta > baseline_tsc * 10) return true;

                    // clock source consistency: if one source is hooked the ratio
                    // between TSC and QPC will be wildly off
                    uint64_t qpc_delta_us = ((qpc_end.QuadPart - qpc_start.QuadPart) * 1000000) / freq.QuadPart;
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
                constexpr uint64_t timing_threshold = 40000 + (CW_DETAIL_RANDOM_CT() % 20000);
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
            // fake response mode is context-specific for callers that want decoy data
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
                        CW_ADSTR(s4, "currentuser");
                        CW_ADSTR(s5, "vmware");  CW_ADSTR(s6, "vbox");

                        const char* checks[] = { s0, s1, s2, s3, s4, s5, s6 };
                        for (auto c : checks) {
                            if (internal_cipher::find_substr(buffer, c)) {
                                CW_ADSTR_ZERO(s0); CW_ADSTR_ZERO(s1); CW_ADSTR_ZERO(s2);
                                CW_ADSTR_ZERO(s3); CW_ADSTR_ZERO(s4); CW_ADSTR_ZERO(s5);
                                CW_ADSTR_ZERO(s6);
                                return true;
                            }
                        }
                        CW_ADSTR_ZERO(s0); CW_ADSTR_ZERO(s1); CW_ADSTR_ZERO(s2);
                        CW_ADSTR_ZERO(s3); CW_ADSTR_ZERO(s4); CW_ADSTR_ZERO(s5);
                        CW_ADSTR_ZERO(s6);
                    }

                    size = sizeof(buffer);
                    if (GetComputerNameA(buffer, &size)) {
                        for (DWORD i = 0; i < size && buffer[i]; ++i)
                            if (buffer[i] >= 'A' && buffer[i] <= 'Z') buffer[i] += 32;

                        CW_ADSTR(c0, "sandbox"); CW_ADSTR(c1, "virus");
                        CW_ADSTR(c2, "malware"); CW_ADSTR(c3, "sample");

                        const char* checks[] = { c0, c1, c2, c3 };
                        for (auto c : checks) {
                            if (internal_cipher::find_substr(buffer, c)) {
                                CW_ADSTR_ZERO(c0); CW_ADSTR_ZERO(c1); CW_ADSTR_ZERO(c2);
                                CW_ADSTR_ZERO(c3);
                                return true;
                            }
                        }
                        CW_ADSTR_ZERO(c0); CW_ADSTR_ZERO(c1); CW_ADSTR_ZERO(c2);
                        CW_ADSTR_ZERO(c3);
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

                    // get adapter info
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
                    bool vendor_vm = detect_vm_vendor();
                    bool artifacts =
                        detect_sandbox_dlls() ||
                        detect_sandbox_names() ||
                        detect_vm_registry() ||
                        detect_vm_mac();

                    if (vendor_vm || artifacts) return true;

                    //
                    // Modern bare-metal Windows often exposes Microsoft's
                    // hypervisor for VBS, Credential Guard, WSL2, or Hyper-V.
                    // Treat the CPUID bit as corroborating evidence instead
                    // of a standalone VM verdict.
                    //
                    if (is_hypervisor_present() && detect_low_resources()) return true;

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
    #define CW_ANTI_VM() ((void)0)
    #define CW_CHECK_VM() (false)
#endif

#if CW_ENABLE_CONTROL_FLOW
    namespace control_flow {
        template<int N>
        CW_NOINLINE bool opaque_true();
        template<int N>
        CW_NOINLINE bool opaque_false();
    }
#endif


#if CW_ENABLE_STRING_ENCRYPTION
    namespace string_encrypt {

        //
        // parameterized feistel cipher — per-site structural variance.
        // round count, shifts, multipliers, and round function are all
        // derived from template key params so each CW_STR() call site
        // compiles to structurally unique code. no shared constants.
        //
        namespace cipher {
            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
            struct config {
                static constexpr uint32_t rounds  = 16u + ((K0 >> 28) & 0xFu);
                static constexpr uint32_t sh0     = 2u + ((K1 >> 0) & 7u);
                static constexpr uint32_t sh1     = 2u + ((K1 >> 3) & 7u);
                static constexpr uint32_t sh2     = 2u + ((K1 >> 6) & 7u);
                static constexpr uint32_t sh3     = 2u + ((K1 >> 9) & 7u);
                static constexpr uint32_t mix_0   = (K0 * 0x45D9F3Bu) ^ K2;
                static constexpr uint32_t mix_1   = (K3 * 0x27D4EB2Du) ^ K1;
                static constexpr uint32_t ks_step = ((K2 ^ K3) | 1u);
                static constexpr uint32_t variant = (K0 >> 24) & 7u;
            };

            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
            static constexpr void encrypt_block(uint32_t& v0, uint32_t& v1) {
                using C = config<K0, K1, K2, K3>;
                uint32_t ks = K0;
                for (uint32_t i = 0; i < C::rounds; ++i) {
                    if constexpr (C::variant == 0) {
                        // arx
                        v0 += (((v1 << C::sh0) ^ (v1 >> C::sh1)) + v1) ^ (ks + K2);
                        ks += C::ks_step;
                        v1 += (((v0 << C::sh2) ^ (v0 >> C::sh3)) + v0) ^ (ks + K3);
                    } else if constexpr (C::variant == 1) {
                        // multiply-first
                        v0 += ((v1 * C::mix_0) ^ (v1 >> C::sh1)) ^ (ks + K1);
                        ks += C::ks_step;
                        v1 += ((v0 * C::mix_1) ^ (v0 >> C::sh3)) ^ (ks + K0);
                    } else if constexpr (C::variant == 2) {
                        // dual-shift
                        v0 += ((v1 << C::sh0) ^ (v1 >> C::sh1) ^ (v1 << C::sh2)) ^ (ks * C::mix_0);
                        ks += C::ks_step;
                        v1 += ((v0 << C::sh2) ^ (v0 >> C::sh3) ^ (v0 << C::sh0)) ^ (ks * C::mix_1);
                    } else if constexpr (C::variant == 3) {
                        // interleaved
                        uint32_t t = v1 ^ (v1 >> C::sh1);
                        v0 += ((t << C::sh0) + (t * C::mix_0)) ^ ks;
                        ks += C::ks_step;
                        t = v0 ^ (v0 >> C::sh3);
                        v1 += ((t << C::sh2) + (t * C::mix_1)) ^ ks;
                    } else if constexpr (C::variant == 4) {
                        // xtea-style: fixed shifts (4,5) with xor key mixing
                        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (ks ^ C::mix_0);
                        ks += C::ks_step;
                        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (ks ^ C::mix_1);
                    } else if constexpr (C::variant == 5) {
                        // speck-like: rotation + mixed add/xor half-rounds
                        uint32_t t0 = (v1 >> C::sh1) | (v1 << (32u - C::sh1));
                        v0 += (t0 + v1) ^ ks;
                        ks += C::ks_step;
                        uint32_t t1 = (v0 << C::sh0) | (v0 >> (32u - C::sh0));
                        v1 ^= (t1 + v0) ^ ks;
                    } else if constexpr (C::variant == 6) {
                        // quadratic: self-squaring for non-linear mixing
                        v0 += ((v1 * v1) ^ (v1 >> C::sh1) ^ C::mix_0) + ks;
                        ks += C::ks_step;
                        v1 += ((v0 * v0) ^ (v0 >> C::sh3) ^ C::mix_1) + ks;
                    } else {
                        // split-merge: half-word decomposition
                        uint32_t hi = v1 >> 16, lo = v1 & 0xFFFFu;
                        v0 += ((hi * C::mix_0) ^ (lo << C::sh0) ^ (lo >> C::sh1)) ^ ks;
                        ks += C::ks_step;
                        hi = v0 >> 16; lo = v0 & 0xFFFFu;
                        v1 += ((lo * C::mix_1) ^ (hi << C::sh2) ^ (hi >> C::sh3)) ^ ks;
                    }
                }
            }

            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
            static constexpr void decrypt_block(uint32_t& v0, uint32_t& v1) {
                using C = config<K0, K1, K2, K3>;
                uint32_t ks = K0 + C::ks_step * C::rounds;
                for (uint32_t i = 0; i < C::rounds; ++i) {
                    if constexpr (C::variant == 0) {
                        v1 -= (((v0 << C::sh2) ^ (v0 >> C::sh3)) + v0) ^ (ks + K3);
                        ks -= C::ks_step;
                        v0 -= (((v1 << C::sh0) ^ (v1 >> C::sh1)) + v1) ^ (ks + K2);
                    } else if constexpr (C::variant == 1) {
                        v1 -= ((v0 * C::mix_1) ^ (v0 >> C::sh3)) ^ (ks + K0);
                        ks -= C::ks_step;
                        v0 -= ((v1 * C::mix_0) ^ (v1 >> C::sh1)) ^ (ks + K1);
                    } else if constexpr (C::variant == 2) {
                        v1 -= ((v0 << C::sh2) ^ (v0 >> C::sh3) ^ (v0 << C::sh0)) ^ (ks * C::mix_1);
                        ks -= C::ks_step;
                        v0 -= ((v1 << C::sh0) ^ (v1 >> C::sh1) ^ (v1 << C::sh2)) ^ (ks * C::mix_0);
                    } else if constexpr (C::variant == 3) {
                        uint32_t t = v0 ^ (v0 >> C::sh3);
                        v1 -= ((t << C::sh2) + (t * C::mix_1)) ^ ks;
                        ks -= C::ks_step;
                        t = v1 ^ (v1 >> C::sh1);
                        v0 -= ((t << C::sh0) + (t * C::mix_0)) ^ ks;
                    } else if constexpr (C::variant == 4) {
                        // xtea-style inverse
                        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (ks ^ C::mix_1);
                        ks -= C::ks_step;
                        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (ks ^ C::mix_0);
                    } else if constexpr (C::variant == 5) {
                        // speck-like inverse: undo xor first, then sub
                        uint32_t t1 = (v0 << C::sh0) | (v0 >> (32u - C::sh0));
                        v1 ^= (t1 + v0) ^ ks;
                        ks -= C::ks_step;
                        uint32_t t0 = (v1 >> C::sh1) | (v1 << (32u - C::sh1));
                        v0 -= (t0 + v1) ^ ks;
                    } else if constexpr (C::variant == 6) {
                        // quadratic inverse
                        v1 -= ((v0 * v0) ^ (v0 >> C::sh3) ^ C::mix_1) + ks;
                        ks -= C::ks_step;
                        v0 -= ((v1 * v1) ^ (v1 >> C::sh1) ^ C::mix_0) + ks;
                    } else {
                        // split-merge inverse
                        uint32_t hi = v0 >> 16, lo = v0 & 0xFFFFu;
                        v1 -= ((lo * C::mix_1) ^ (hi << C::sh2) ^ (hi >> C::sh3)) ^ ks;
                        ks -= C::ks_step;
                        hi = v1 >> 16; lo = v1 & 0xFFFFu;
                        v0 -= ((hi * C::mix_0) ^ (lo << C::sh0) ^ (lo >> C::sh1)) ^ ks;
                    }
                }
            }

            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3, typename ByteT>
            static constexpr void encrypt_buffer(ByteT* data, size_t len) {
                for (size_t i = 0; i + 7 < len; i += 8) {
                    uint32_t v0 = static_cast<uint32_t>(static_cast<uint8_t>(data[i]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+1])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+2])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+3])) << 24);
                    uint32_t v1 = static_cast<uint32_t>(static_cast<uint8_t>(data[i+4]))
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+5])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+6])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(data[i+7])) << 24);

                    encrypt_block<K0, K1, K2, K3>(v0, v1);

                    data[i]   = static_cast<ByteT>(static_cast<uint8_t>(v0));
                    data[i+1] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 8));
                    data[i+2] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 16));
                    data[i+3] = static_cast<ByteT>(static_cast<uint8_t>(v0 >> 24));
                    data[i+4] = static_cast<ByteT>(static_cast<uint8_t>(v1));
                    data[i+5] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 8));
                    data[i+6] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 16));
                    data[i+7] = static_cast<ByteT>(static_cast<uint8_t>(v1 >> 24));
                }

                // tail bytes: position-dependent xor from key params
                size_t tail = (len / 8) * 8;
                for (size_t i = tail; i < len; ++i) {
                    uint32_t stream = K0 ^ (K1 * static_cast<uint32_t>(i + 1));
                    stream *= K2 | 1u;
                    stream ^= stream >> 16;
                    stream += K3;
                    data[i] = static_cast<ByteT>(static_cast<uint8_t>(data[i]) ^
                        static_cast<uint8_t>(stream));
                }
            }

            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3, typename ByteT>
            static constexpr void decrypt_buffer(ByteT* data, size_t len) {
                // tail first (xor stream is self-inverse)
                size_t tail = (len / 8) * 8;
                for (size_t i = tail; i < len; ++i) {
                    uint32_t stream = K0 ^ (K1 * static_cast<uint32_t>(i + 1));
                    stream *= K2 | 1u;
                    stream ^= stream >> 16;
                    stream += K3;
                    data[i] = static_cast<ByteT>(static_cast<uint8_t>(data[i]) ^
                        static_cast<uint8_t>(stream));
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

                    decrypt_block<K0, K1, K2, K3>(v0, v1);

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

            // compile-time proof that encrypt/decrypt are exact inverses
            template<uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
            static consteval bool verify_roundtrip() {
                uint32_t v0 = 0xDEADBEEF, v1 = 0xCAFEBABE;
                uint32_t orig_v0 = v0, orig_v1 = v1;
                encrypt_block<K0, K1, K2, K3>(v0, v1);
                decrypt_block<K0, K1, K2, K3>(v0, v1);
                return v0 == orig_v0 && v1 == orig_v1;
            }

            // exercises all 8 round function variants + edge cases
            static_assert(verify_roundtrip<0x00345678, 0x9ABCDEF0, 0x11111111, 0x22222222>()); // variant 0: arx
            static_assert(verify_roundtrip<0x01ADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0x01020304>()); // variant 1: multiply-first
            static_assert(verify_roundtrip<0x02000000, 0x55555555, 0xAAAAAAAA, 0x33333333>()); // variant 2: dual-shift
            static_assert(verify_roundtrip<0x03C0FFEE, 0x12345678, 0x87654321, 0xDEADCAFE>()); // variant 3: interleaved
            static_assert(verify_roundtrip<0x04B00B1E, 0xFACEFEED, 0xCAFED00D, 0xBAADF00D>()); // variant 4: xtea-style
            static_assert(verify_roundtrip<0x05DECADE, 0xC0DEC0DE, 0x8BADF00D, 0xDEFEC8ED>()); // variant 5: speck-like
            static_assert(verify_roundtrip<0x06F00BAA, 0xABADBABE, 0xBEEFCAFE, 0xFEEDFACE>()); // variant 6: quadratic
            static_assert(verify_roundtrip<0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF>()); // variant 7: split-merge
            static_assert(verify_roundtrip<0, 0, 0, 0>());                                     // edge: all zeros

            //
            // lightweight stream cipher for runtime re-keying.
            // position-dependent xor — self-inverse, so encrypt == decrypt (always ensure encrypt == decrypt please if you're modifying).
            // used where keys are generated at runtime and can't be template params.
            //
            template<typename ByteT>
            static CW_FORCEINLINE void rt_encrypt(ByteT* data, size_t len,
                                                  uint32_t k0, uint32_t k1,
                                                  uint32_t k2, uint32_t k3) {
                for (size_t i = 0; i < len; ++i) {
                    uint32_t stream = k0 ^ (k1 * static_cast<uint32_t>(i + 1));
                    stream *= k2 | 1u;
                    stream ^= stream >> 16;
                    stream += k3;
                    data[i] = static_cast<ByteT>(static_cast<uint8_t>(data[i]) ^
                        static_cast<uint8_t>(stream));
                }
            }
        }

        template<typename Char, size_t N, uint32_t K0, uint32_t K1,
                 uint32_t K2, uint32_t K3, bool Layered = false>
        struct literal_payload {
            std::array<uint8_t, N * sizeof(Char)> bytes{};
            constexpr literal_payload(const Char (&text)[N]) {
                using U = std::make_unsigned_t<Char>;
                for (size_t i = 0; i < N; ++i)
                    for (size_t j = 0; j < sizeof(Char); ++j)
                        bytes[i * sizeof(Char) + j] = static_cast<uint8_t>(static_cast<U>(text[i]) >> (j * 8));
                cipher::encrypt_buffer<K0, K1, K2, K3>(bytes.data(), bytes.size());
                if constexpr (Layered)
                    cipher::encrypt_buffer<K3 ^ 0x9E3779B9u, K2, K1, K0>(bytes.data(), bytes.size());
            }
            CW_NOINLINE void copy_to(Char* output) const {
                std::array<uint8_t, N * sizeof(Char)> temporary{};
                const volatile uint8_t* source = bytes.data();
                for (size_t i = 0; i < bytes.size(); ++i) temporary[i] = source[i];
                if constexpr (Layered)
                    cipher::decrypt_buffer<K3 ^ 0x9E3779B9u, K2, K1, K0>(temporary.data(), temporary.size());
                cipher::decrypt_buffer<K0, K1, K2, K3>(temporary.data(), temporary.size());
                using U = std::make_unsigned_t<Char>;
                for (size_t i = 0; i < N; ++i) {
                    U value = 0;
                    for (size_t j = 0; j < sizeof(Char); ++j)
                        value |= static_cast<U>(temporary[i * sizeof(Char) + j]) << (j * 8);
                    output[i] = std::bit_cast<Char>(value);
                }
                detail::wipe(temporary.data(), temporary.size());
            }
        };

        template<typename Char, size_t N, uint32_t K0, uint32_t K1,
                 uint32_t K2, uint32_t K3, bool Layered = false>
        class string_storage {
            literal_payload<Char, N, K0, K1, K2, K3, Layered> payload;
            mutable std::array<Char, N> plain{};
            mutable std::atomic<bool> decrypted{false};
            mutable std::mutex mutex;
        public:
            constexpr string_storage(const Char (&text)[N]) : payload(text) {}
            template<size_t... I>
            constexpr string_storage(const Char (&text)[N], std::index_sequence<I...>) : payload(text) {}
            CW_NOINLINE const Char* get() const {
                if (!decrypted.load(std::memory_order_acquire)) {
                    std::lock_guard<std::mutex> guard(mutex);
                    if (!decrypted.load(std::memory_order_relaxed)) {
                        payload.copy_to(plain.data());
                        decrypted.store(true, std::memory_order_release);
                    }
                }
                return plain.data();
            }
            void copy_to(Char* output) const { payload.copy_to(output); }
            operator const Char*() const { return get(); }
            ~string_storage() { detail::wipe(plain.data(), sizeof(plain)); }
        };

        template<size_t N, uint32_t K0 = CW_DETAIL_RANDOM_CT(), uint32_t K1 = CW_DETAIL_RANDOM_CT() ^ 0xA341316Cu,
                 uint32_t K2 = CW_DETAIL_RANDOM_CT() ^ 0xC8013EA4u, uint32_t K3 = CW_DETAIL_RANDOM_CT() ^ 0xAD90777Du>
        class encrypted_string : public string_storage<char, N, K0, K1, K2, K3> {
        public:
            using string_storage<char, N, K0, K1, K2, K3>::string_storage;
        };
        template<size_t N> encrypted_string(const char (&)[N]) -> encrypted_string<N>;

        template<size_t N, uint32_t K0 = CW_DETAIL_RANDOM_CT(), uint32_t K1 = CW_DETAIL_RANDOM_CT() ^ 0xA341316Cu,
                 uint32_t K2 = CW_DETAIL_RANDOM_CT() ^ 0xC8013EA4u, uint32_t K3 = CW_DETAIL_RANDOM_CT() ^ 0xAD90777Du>
        class layered_encrypted_string : public string_storage<char, N, K0, K1, K2, K3, true> {
        public:
            using string_storage<char, N, K0, K1, K2, K3, true>::string_storage;
        };
        template<size_t N> layered_encrypted_string(const char (&)[N]) -> layered_encrypted_string<N>;

        template<size_t N, uint32_t K0 = CW_DETAIL_RANDOM_CT(), uint32_t K1 = CW_DETAIL_RANDOM_CT() ^ 0xA341316Cu,
                 uint32_t K2 = CW_DETAIL_RANDOM_CT() ^ 0xC8013EA4u, uint32_t K3 = CW_DETAIL_RANDOM_CT() ^ 0xAD90777Du>
        class encrypted_wstring : public string_storage<wchar_t, N, K0, K1, K2, K3> {
        public:
            using string_storage<wchar_t, N, K0, K1, K2, K3>::string_storage;
        };
        template<size_t N> encrypted_wstring(const wchar_t (&)[N]) -> encrypted_wstring<N>;

        template<size_t N>
        class stack_encrypted_string {
            std::array<char, N> buffer{};
        public:
            template<uint32_t A, uint32_t B, uint32_t C, uint32_t D>
            explicit stack_encrypted_string(const literal_payload<char, N, A, B, C, D>& payload) {
                payload.copy_to(buffer.data());
            }
            template<size_t M, uint32_t A, uint32_t B, uint32_t C, uint32_t D>
            stack_encrypted_string(const encrypted_string<M, A, B, C, D>& enc) {
                static_assert(N >= M, "The destination must fit the entire string");
                enc.copy_to(buffer.data());
            }
            const char* get() const & { return buffer.data(); }
            const char* get() const && = delete;
            operator const char*() const & { return get(); }
            operator const char*() const && = delete;
            ~stack_encrypted_string() { detail::wipe(buffer.data(), N); }
        };

        // Kept for source compatibility with callers using this internal helper.
        template<uint32_t Pad> inline void size_pad() { CW_COMPILER_BARRIER(); }
    }

    // string encryption macros
    // constinit requires encrypted initialization; the plaintext cache is populated on first access.
#define CW_STR(s) \
    static_cast<const char*>(([]() CW_NOINLINE -> const char* { \
        constinit static cloakwork::string_encrypt::encrypted_string<sizeof(s), \
            CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT()> enc(s); \
        cloakwork::string_encrypt::size_pad<CW_RANDOM_CT()>(); \
        return enc.get(); \
    }()))

#define CW_STR_LAYERED(s) \
    static_cast<const char*>(([]() CW_NOINLINE -> const char* { \
        constinit static cloakwork::string_encrypt::layered_encrypted_string<sizeof(s), \
            CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT()> enc(s); \
        cloakwork::string_encrypt::size_pad<CW_RANDOM_CT()>(); \
        return enc.get(); \
    }()))

#define CW_STR_STACK(s) \
    ([&]() CW_NOINLINE { \
        static constexpr cloakwork::string_encrypt::literal_payload<char, sizeof(s), \
            CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT()> enc(s); \
        return cloakwork::string_encrypt::stack_encrypted_string<sizeof(s)>(enc); \
    }())

#define CW_WSTR(s) \
    static_cast<const wchar_t*>(([]() CW_NOINLINE -> const wchar_t* { \
        constinit static cloakwork::string_encrypt::encrypted_wstring<sizeof(s)/sizeof(wchar_t), \
            CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT(), CW_RANDOM_CT()> enc(s); \
        cloakwork::string_encrypt::size_pad<CW_RANDOM_CT()>(); \
        return enc.get(); \
    }()))

// Stack string builder. Compilers may combine the initializers into a string literal.
// usage: CW_STACK_STR(name, 'h','e','l','l','o','\0')
#define CW_STACK_STR(name, ...) \
    char name[] = { __VA_ARGS__ }; \
    do { \
        constexpr uint8_t _cw_ssk = static_cast<uint8_t>(CW_RANDOM_CT() | 1); \
        volatile uint8_t* _cw_ssp = reinterpret_cast<volatile uint8_t*>(name); \
        for (size_t _cw_ssi = 0; _cw_ssi < sizeof(name); ++_cw_ssi) { \
            _cw_ssp[_cw_ssi] ^= _cw_ssk; \
            _cw_ssp[_cw_ssi] ^= _cw_ssk; \
        } \
        CW_COMPILER_BARRIER(); \
    } while(0)

#else
    #define CW_STR(s) (s)
    #define CW_STR_LAYERED(s) (s)
    #define CW_STR_STACK(s) (s)
    #define CW_WSTR(s) (s)
    #define CW_STACK_STR(name, ...) char name[] = { __VA_ARGS__ }
#endif

#if !CW_KERNEL_MODE
    namespace detail {


        // Four Feistel rounds on byte halves. This is reversible obfuscation,
        // not a cryptographic cipher. All intermediates have defined unsigned semantics.
        constexpr uint8_t byte_round(uint8_t right, uint8_t key, unsigned round) {
            return static_cast<uint8_t>((right * right + right * (key | 1u) +
                (key >> (round & 3u))) ^ (right << 1u)) & 15u;
        }

        constexpr uint8_t encode_byte(uint8_t value, uint8_t key) {
            unsigned left = value >> 4u, right = value & 15u;
            for (unsigned round = 0; round < 4; ++round) {
                unsigned next = left ^ byte_round(static_cast<uint8_t>(right), key, round);
                left = right;
                right = next;
            }
            return static_cast<uint8_t>((left << 4u) | right);
        }

        constexpr uint8_t decode_byte(uint8_t value, uint8_t key) {
            unsigned left = value >> 4u, right = value & 15u;
            for (unsigned round = 4; round-- > 0;) {
                unsigned previous = right ^ byte_round(static_cast<uint8_t>(left), key, round);
                right = left;
                left = previous;
            }
            return static_cast<uint8_t>((left << 4u) | right);
        }

        template<Arithmetic T>
        class encoded_storage {
            std::array<uint8_t, sizeof(T)> bytes{};
            std::array<uint8_t, sizeof(T)> keys{};
        public:
            encoded_storage() { set(T{}); }
            explicit encoded_storage(T value) { set(value); }
            ~encoded_storage() { wipe(bytes.data(), bytes.size()); wipe(keys.data(), keys.size()); }

            CW_NOINLINE void set(T value) {
                auto plain = std::bit_cast<std::array<uint8_t, sizeof(T)>>(value);
                for (size_t i = 0; i < sizeof(T); ++i) {
                    keys[i] = static_cast<uint8_t>(CW_RANDOM_RT());
                    bytes[i] = encode_byte(plain[i], keys[i]);
                }
                wipe(plain.data(), plain.size());
            }
            CW_NOINLINE T get() const {
                std::array<uint8_t, sizeof(T)> plain{};
                for (size_t i = 0; i < sizeof(T); ++i)
                    plain[i] = decode_byte(bytes[i], keys[i]);
                T result = std::bit_cast<T>(plain);
                wipe(plain.data(), plain.size());
                return result;
            }
        };
    }
#endif

#if CW_ENABLE_VALUE_OBFUSCATION

    namespace mba {

        /*++

        MBA transforms.

        --*/

        template<Integral T>
        using clean_integral_t = std::remove_cv_t<T>;

        template<Integral T>
        using unsigned_integral_t = std::make_unsigned_t<std::conditional_t<std::is_same_v<clean_integral_t<T>, bool>, uint8_t, clean_integral_t<T>>>;

        template<Integral T>
        CW_FORCEINLINE clean_integral_t<T> from_unsigned(unsigned_integral_t<T> value) {
            using C = clean_integral_t<T>;
            if constexpr (std::is_same_v<C, bool>) {
                return value != 0;
            } else {
                return std::bit_cast<C>(value);
            }
        }

        //
        // Deep MBA addition variant 0: nested De Morgan with carry propagation.
        // x + y is computed through 3 layers of bitwise transforms with volatile
        // intermediates that prevent the optimizer from collapsing back to 'add'.
        //
        template<Integral T>
        CW_NOINLINE clean_integral_t<T> add_deep(T x, T y) {
            CW_COMPILER_BARRIER();
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            volatile U vx = static_cast<U>(x), vy = static_cast<U>(y);
            CW_COMPILER_BARRIER();
            // depth 1: (x|y) and (x&y) via De Morgan
            volatile U t0 = ~(~vx & ~vy);       // x | y
            volatile U t1 = ~(~vx | ~vy);       // x & y
            CW_COMPILER_BARRIER();
            // depth 2: half-sum and carry from the above
            U a = t0, b = t1;
            volatile U half = a ^ b;             // (x|y) ^ (x&y) = x ^ y
            volatile U carry = (a & b) << 1;     // 2 * ((x|y) & (x&y)) = 2*(x&y)
            CW_COMPILER_BARRIER();
            // depth 3: recombine via MBA identity
            U h = half, c = carry;
            volatile U result = (h ^ c) + ((h & c) << 1);
            CW_COMPILER_BARRIER();
            return from_unsigned<T>(result);
        }

        //
        // Deep MBA addition variant 1: XOR expanded through De Morgan.
        // x ^ y = (~x & y) | (x & ~y), then carry via nested MBA.
        // different instruction pattern from variant 0 at each call site.
        //
        template<Integral T>
        CW_NOINLINE clean_integral_t<T> add_deep_alt(T x, T y) {
            CW_COMPILER_BARRIER();
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            volatile U vx = static_cast<U>(x), vy = static_cast<U>(y);
            CW_COMPILER_BARRIER();
            U a = ~static_cast<U>(vx) & static_cast<U>(vy);
            U b = static_cast<U>(vx) & ~static_cast<U>(vy);
            volatile U c = a | b;                // x ^ y via de Morgan
            volatile U d = ~(~vx | ~vy);         // x & y via de Morgan
            CW_COMPILER_BARRIER();
            U cv = c, dv = d;
            volatile U e = dv + dv;              // 2*(x&y)
            CW_COMPILER_BARRIER();
            // final: (x^y) + 2*(x&y) but both terms computed through indirection
            U ev = e;
            volatile U result = (cv ^ ev) + ((cv & ev) << 1);
            CW_COMPILER_BARRIER();
            return from_unsigned<T>(result);
        }

        // Product terms couple both operands. The cancellation remains algebraically
        // simplifiable; volatile materialization only constrains compiler optimization.
        template<Integral T, int Variant = 2>
        CW_NOINLINE clean_integral_t<T> add_nonlinear(T x, T y) {
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            const U a = static_cast<U>(x), b = static_cast<U>(y);
            volatile U product = (a ^ static_cast<U>(Variant)) * (b | U{1});
            volatile U mixed = (a ^ b) + ((a & b) << 1) + product;
            CW_COMPILER_BARRIER();
            return from_unsigned<T>(static_cast<unsigned_integral_t<T>>(mixed - product));
        }

        // compile-time variant selection gives each call site a different expansion
        template<Integral T, int Variant = 0>
        CW_FORCEINLINE clean_integral_t<T> add_mba(T x, T y) {
            if constexpr ((Variant & 3) == 0) return add_deep(x, y);
            else if constexpr ((Variant & 3) == 1) return add_deep_alt(x, y);
            else return add_nonlinear<T, Variant>(x, y);
        }

        //
        // Deep subtraction: x - y = x + (~y + 1)
        // both the negation and the addition are expanded through MBA.
        //
        template<Integral T>
        CW_NOINLINE clean_integral_t<T> sub_deep(T x, T y) {
            CW_COMPILER_BARRIER();
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            volatile U vy = static_cast<U>(y);
            CW_COMPILER_BARRIER();
            U neg_y = ~static_cast<U>(vy);
            U one = static_cast<U>(1);
            // neg_y + 1 via MBA
            volatile U t0 = ~(~neg_y & ~one);       // neg_y | 1
            volatile U t1 = ~(~neg_y | ~one);       // neg_y & 1
            CW_COMPILER_BARRIER();
            U a0 = t0, a1 = t1;
            volatile U neg_result = (a0 ^ a1) + ((a0 & a1) << 1);
            CW_COMPILER_BARRIER();
            // x + neg_result via different MBA path
            volatile U vx = static_cast<U>(x);
            CW_COMPILER_BARRIER();
            U xv = vx, nr = neg_result;
            U da = ~xv & nr;
            U db = xv & ~nr;
            volatile U dc = da | db;                 // x ^ neg_result
            volatile U dd = ~(~xv | ~nr);            // x & neg_result
            CW_COMPILER_BARRIER();
            U cv = dc;
            volatile U result = cv + (static_cast<U>(dd) << 1);
            CW_COMPILER_BARRIER();
            return from_unsigned<T>(result);
        }

        template<Integral T, int Variant = 0>
        CW_FORCEINLINE clean_integral_t<T> sub_mba(T x, T y) {
            if constexpr ((Variant & 1) == 0) return sub_deep(x, y);
            else {
                using U = unsigned_integral_t<T>;
                return add_mba<clean_integral_t<T>, Variant>(x, from_unsigned<T>(static_cast<U>(U{0} - static_cast<U>(y))));
            }
        }

        // x * 2 routed through deep add
        template<Integral T>
        CW_FORCEINLINE clean_integral_t<T> mul2_mba(T x) {
            return add_mba(x, x);
        }

        // negation via deep MBA: -x = ~x + 1
        template<Integral T>
        CW_FORCEINLINE clean_integral_t<T> neg_mba(T x) {
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            U ux = static_cast<U>(x);
            return from_unsigned<T>(add_mba(static_cast<clean_integral_t<T>>(~ux), static_cast<clean_integral_t<T>>(1)));
        }

        // bitwise ops stay shallow -- De Morgan transforms are less
        // recognizable than arithmetic MBA and simplifiers don't target them
        template<Integral T>
        CW_FORCEINLINE constexpr clean_integral_t<T> and_mba(T x, T y) {
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            U result = ~(~static_cast<U>(x) | ~static_cast<U>(y));
            return from_unsigned<T>(static_cast<unsigned_integral_t<T>>(result));
        }

        template<Integral T>
        CW_FORCEINLINE constexpr clean_integral_t<T> or_mba(T x, T y) {
            using U = std::conditional_t<(sizeof(T) < sizeof(unsigned)), unsigned, unsigned_integral_t<T>>;
            U result = ~(~static_cast<U>(x) & ~static_cast<U>(y));
            return from_unsigned<T>(static_cast<unsigned_integral_t<T>>(result));
        }

        template<Integral A, Integral B>
        CW_FORCEINLINE auto and_mba_once(A a, B b) {
            using R = decltype(a & b);
            return and_mba<R>(static_cast<R>(a), static_cast<R>(b));
        }
        template<Integral A, Integral B>
        CW_FORCEINLINE auto or_mba_once(A a, B b) {
            using R = decltype(a | b);
            return or_mba<R>(static_cast<R>(a), static_cast<R>(b));
        }

        template<Integral A, Integral B>
        CW_FORCEINLINE auto xor_mba_once(A a, B b) {
            using R = clean_integral_t<decltype(a ^ b)>;
            R ra = static_cast<R>(a);
            R rb = static_cast<R>(b);
            return sub_mba(or_mba(ra, rb), and_mba(ra, rb));
        }
    }

    template<Arithmetic T>
    class obfuscated_value {
        detail::encoded_storage<T> storage;
        mutable CW_MUTEX mutex;
    public:
        obfuscated_value() = default;
        obfuscated_value(T value) : storage(value) {}
        obfuscated_value(const obfuscated_value& other) : storage(other.get()) {}
        obfuscated_value& operator=(const obfuscated_value& other) {
            if (this != &other) set(other.get());
            return *this;
        }
        void set(T value) { CW_LOCK_GUARD(mutex); storage.set(value); }
        T get() const { CW_LOCK_GUARD(mutex); return storage.get(); }
        operator T() const { return get(); }
        obfuscated_value& operator=(T value) { set(value); return *this; }
    };

    template<Integral T>
    class mba_obfuscated {
        using U = mba::unsigned_integral_t<T>;
        U encoded{}, key1{}, key2{};
        mutable CW_MUTEX mutex;
    public:
        mba_obfuscated() : mba_obfuscated(T{}) {}
        mba_obfuscated(T value) { set(value); }
        mba_obfuscated(const mba_obfuscated& other) : mba_obfuscated(other.get()) {}
        mba_obfuscated& operator=(const mba_obfuscated& other) {
            if (this != &other) set(other.get());
            return *this;
        }
        CW_NOINLINE void set(T value) {
            CW_LOCK_GUARD(mutex);
            key1 = static_cast<U>(CW_RANDOM_RT());
            key2 = static_cast<U>(CW_RANDOM_RT());
            encoded = mba::add_mba<U, 2>(static_cast<U>(value), key1) ^ key2;
        }
        CW_NOINLINE T get() const {
            CW_LOCK_GUARD(mutex);
            return mba::from_unsigned<T>(mba::sub_mba<U>(static_cast<U>(encoded ^ key2), key1));
        }
        operator T() const { return get(); }
        mba_obfuscated& operator=(T value) { set(value); return *this; }
    };


    namespace bool_obfuscation {

        // CW_NOINLINE prevents LTCG from constant-folding the result
        template<int N = CW_DETAIL_RAND_CT(0, 7)>
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

        template<int N = CW_DETAIL_RAND_CT(0, 7)>
        CW_NOINLINE bool obfuscated_false() {
            return !obfuscated_true<N>();
        }

        template<int N = CW_DETAIL_RAND_CT(1, 1000)>
        CW_FORCEINLINE bool obfuscate_bool(bool value) {
            CW_COMPILER_BARRIER();

            // transform: value = (value AND true) OR (false AND anything)
            // mathematically equivalent to just 'value', with extra analysis noise
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

        template<uint8_t Key1 = static_cast<uint8_t>(CW_DETAIL_RAND_CT(1, 255)),
                 uint8_t Key2 = static_cast<uint8_t>(CW_DETAIL_RAND_CT(1, 255)),
                 uint8_t Key3 = static_cast<uint8_t>(CW_DETAIL_RAND_CT(1, 255))>
        class obfuscated_bool {
            obfuscated_value<bool> value;
        public:
            obfuscated_bool() : value(false) {}
            obfuscated_bool(bool initial) : value(initial) {}
            bool get() const { return value.get(); }
            void set(bool next) { value.set(next); }
            operator bool() const { return get(); }
            obfuscated_bool& operator=(bool next) { set(next); return *this; }
            obfuscated_bool operator!() const { return obfuscated_bool(!get()); }
            obfuscated_bool operator&&(bool other) const { return obfuscated_bool(get() && other); }
            obfuscated_bool operator||(bool other) const { return obfuscated_bool(get() || other); }
        };
    }

    #define CW_TRUE (cloakwork::bool_obfuscation::obfuscated_true<CW_RAND_CT(1, 1000)>())
    #define CW_FALSE (cloakwork::bool_obfuscation::obfuscated_false<CW_RAND_CT(1, 1000)>())
    #define CW_BOOL(x) (cloakwork::bool_obfuscation::obfuscate_bool<CW_RAND_CT(1, 1000)>(x))

    #define CW_ADD(a, b) (cloakwork::mba::add_mba<decltype((a)+(b)), CW_RAND_CT(0, 7)>((a), (b)))
    #define CW_SUB(a, b) (cloakwork::mba::sub_mba<decltype((a)-(b)), CW_RAND_CT(0, 7)>((a), (b)))
    #define CW_AND(a, b) (cloakwork::mba::and_mba_once((a), (b)))
    #define CW_OR(a, b) (cloakwork::mba::or_mba_once((a), (b)))

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

        /*++

        Control flow transforms.

        --*/


        // decompiler-resistant opaque predicates based on number-theoretic
        // invariants. each predicate relies on a provably-true mathematical
        // property but produces non-trivial computation in the binary.

        namespace opaque_detail {

            static CW_FORCEINLINE uint32_t soft_popcount32(uint32_t value) {
                value = value - ((value >> 1) & 0x55555555u);
                value = (value & 0x33333333u) + ((value >> 2) & 0x33333333u);
                value = (value + (value >> 4)) & 0x0F0F0F0Fu;
                return (value * 0x01010101u) >> 24;
            }

            static CW_FORCEINLINE uint32_t soft_crc32_u32(uint32_t seed, uint32_t value) {
                uint32_t crc = ~seed;
                for (int i = 0; i < 4; ++i) {
                    crc ^= static_cast<uint8_t>(value >> (i * 8));
                    for (int bit = 0; bit < 8; ++bit)
                        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
                }
                return ~crc;
            }

            //
            // Predicate 0: quadratic residue mod 4.
            // For any integer x, x^2 mod 4 is always 0 or 1.
            // Even: (2k)^2 = 4k^2 -> mod 4 = 0
            // Odd:  (2k+1)^2 = 4k^2+4k+1 -> mod 4 = 1
            //
            static CW_NOINLINE bool quadratic_residue_true(uint32_t seed) {
                volatile uint32_t x = seed ^ static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(&x));
                CW_COMPILER_BARRIER();
                uint32_t val = x;
                volatile uint32_t sq = val * val;
                CW_COMPILER_BARRIER();
                volatile uint32_t rem = sq & 3u;
                return (rem == 0u) || (rem == 1u);
            }

            //
            // Predicate 1: product of consecutive integers is always even.
            // n*(n+1) must be even because one of {n, n+1} is always even.
            //
            static CW_NOINLINE bool consecutive_product_true() {
                volatile uint32_t n = static_cast<uint32_t>(__rdtsc() & 0xFFFF);
                CW_COMPILER_BARRIER();
                uint32_t val = n;
                volatile uint32_t product = val * (val + 1u);
                CW_COMPILER_BARRIER();
                return (product & 1u) == 0u;
            }

            //
            // Predicate 2: Gauss summation identity.
            // sum(0..n) computed via closed form n*(n+1)/2 and via iterative
            // accumulation must agree. two independent codepaths that the
            // compiler can't fold because of volatile intermediates.
            //
            static CW_NOINLINE bool gauss_sum_true() {
                volatile uint32_t n = (static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(&n)) >> 4) & 0x1F;
                CW_COMPILER_BARRIER();
                uint32_t limit = n | 4u; // at least 4 iterations

                // path A: closed form
                volatile uint32_t closed = (limit * (limit + 1u)) >> 1;
                CW_COMPILER_BARRIER();

                // path B: iterative
                volatile uint32_t acc = 0;
                for (volatile uint32_t i = 0; i <= limit; ++i)
                    acc += i;
                CW_COMPILER_BARRIER();

                return closed == acc;
            }

            //
            // Predicate 3: popcount(x) + popcount(~x) == 32 for any 32-bit x.
            // every bit is set in exactly one of {x, ~x}, so the total popcount
            // is always the bitwidth. software popcount avoids feature-gated
            // CPU instructions in default builds.
            //
            static CW_NOINLINE bool popcount_complement_true() {
                volatile uint32_t x = static_cast<uint32_t>(__rdtsc());
                CW_COMPILER_BARRIER();
                uint32_t val = x;
                volatile uint32_t pc1 = soft_popcount32(val);
                volatile uint32_t pc2 = soft_popcount32(~val);
                CW_COMPILER_BARRIER();
                return (pc1 + pc2) == 32u;
            }

            //
            // Predicate 4: CRC32 of the same value computed through separate
            // volatile paths always produces equal results. the software CRC
            // path is noisier than a single instruction but does not fault on
            // older CPUs or clang-cl default targets.
            //
            static CW_NOINLINE bool crc_self_true() {
                volatile uint32_t val = static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(&val));
                CW_COMPILER_BARRIER();
                uint32_t v = val;
                volatile uint32_t c1 = soft_crc32_u32(0, v);
                CW_COMPILER_BARRIER();
                volatile uint32_t c2 = soft_crc32_u32(0, v);
                CW_COMPILER_BARRIER();
                return c1 == c2;
            }

            //
            // Predicate 5: Bezout's identity / Euclidean GCD property.
            // gcd(a, b) always divides a. we compute the GCD via the Euclidean
            // algorithm (real iterative work) and then verify a % gcd == 0.
            // the loop and modular arithmetic look like genuine algorithmic code.
            //
            static CW_NOINLINE bool bezout_true() {
                volatile uint32_t a = static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(&a)) | 1u;
                volatile uint32_t b = static_cast<uint32_t>(__rdtsc()) | 1u;
                CW_COMPILER_BARRIER();
                uint32_t va = a, vb = b;
                // Euclidean GCD
                while (vb != 0) {
                    uint32_t t = vb;
                    vb = va % vb;
                    va = t;
                }
                volatile uint32_t orig_a = a;
                CW_COMPILER_BARRIER();
                return (orig_a % va) == 0;
            }

            //
            // Predicate 6: bit decomposition identity.
            // for any nonzero x, the span from lowest to highest set bit plus
            // leading and trailing zeros equals the bitwidth. popcount is bounded
            // by the span. uses BSF, BSR, POPCNT — three distinct hardware
            // instructions the decompiler can't fold.
            //
            static CW_NOINLINE bool bit_decompose_true() {
                volatile uint32_t x = static_cast<uint32_t>(__rdtsc()) | 1u;
                CW_COMPILER_BARRIER();
                uint32_t v = x;
                unsigned long bsf_idx, bsr_idx;
                _BitScanForward(&bsf_idx, v);
                _BitScanReverse(&bsr_idx, v);
                volatile uint32_t pc = soft_popcount32(v);
                CW_COMPILER_BARRIER();
                uint32_t leading  = 31u - bsr_idx;
                uint32_t trailing = bsf_idx;
                uint32_t span     = bsr_idx - bsf_idx + 1u;
                return (leading + span + trailing) == 32u && pc <= span;
            }

            //
            // Predicate 7: modular multiplicative inverse via Hensel lifting.
            // for any odd x, x * modinv(x) == 1 (mod 2^32). we compute the
            // inverse using Newton iteration which converges in 4 steps for
            // 32-bit integers. the resulting code looks like real crypto work.
            //
            static CW_NOINLINE bool modinv_true() {
                volatile uint32_t x = (static_cast<uint32_t>(__rdtsc()) | 1u);
                CW_COMPILER_BARRIER();
                uint32_t v = x;
                // Newton's method for modular inverse:
                // if y ~= v^{-1} mod 2^k, then y*(2 - v*y) ~= v^{-1} mod 2^{2k}
                uint32_t inv = v; // initial: v*v == 1 mod 2 for odd v
                inv = inv * (2u - v * inv); // accurate mod 2^4
                inv = inv * (2u - v * inv); // accurate mod 2^8
                inv = inv * (2u - v * inv); // accurate mod 2^16
                inv = inv * (2u - v * inv); // accurate mod 2^32
                volatile uint32_t check = v * inv;
                CW_COMPILER_BARRIER();
                return check == 1u;
            }
        }

        // rotate between predicate types per call site using compile-time random.
        // CW_NOINLINE prevents LTCG from inlining and resolving the predicate chain.
        template<int N = CW_DETAIL_RAND_CT(0, 7)>
        CW_NOINLINE bool opaque_true() {
            volatile uint32_t seed = static_cast<uint32_t>(
                reinterpret_cast<uintptr_t>(&seed) & 0xFF) + static_cast<uint32_t>(N);
            CW_COMPILER_BARRIER();

            constexpr int primary = N % 8;
            constexpr int secondary = (N * 3 + 1) % 8;

            bool result;
            if constexpr (primary == 0) result = opaque_detail::quadratic_residue_true(seed);
            else if constexpr (primary == 1) result = opaque_detail::consecutive_product_true();
            else if constexpr (primary == 2) result = opaque_detail::gauss_sum_true();
            else if constexpr (primary == 3) result = opaque_detail::popcount_complement_true();
            else if constexpr (primary == 4) result = opaque_detail::crc_self_true();
            else if constexpr (primary == 5) result = opaque_detail::bezout_true();
            else if constexpr (primary == 6) result = opaque_detail::bit_decompose_true();
            else result = opaque_detail::modinv_true();

            // chain with a second predicate to increase decompiler confusion
            if constexpr (secondary == 0) result = result && opaque_detail::quadratic_residue_true(seed + 1);
            else if constexpr (secondary == 1) result = result && opaque_detail::consecutive_product_true();
            else if constexpr (secondary == 2) result = result && opaque_detail::gauss_sum_true();
            else if constexpr (secondary == 3) result = result && opaque_detail::popcount_complement_true();
            else if constexpr (secondary == 4) result = result && opaque_detail::crc_self_true();
            else if constexpr (secondary == 5) result = result && opaque_detail::bezout_true();
            else if constexpr (secondary == 6) result = result && opaque_detail::bit_decompose_true();
            else result = result && opaque_detail::modinv_true();

            CW_COMPILER_BARRIER();
            return result;
        }

        template<int N = CW_DETAIL_RAND_CT(0, 7)>
        CW_NOINLINE bool opaque_false() {
            // negate a true predicate - same decompiler resistance
            return !opaque_true<N>();
        }

        // control flow flattening via switch-case state machine
        // generates a real dispatcher that IDA/Hex-Rays shows as a state machine
        // state transitions are XOR-encoded with a compile-time key
        template<uint32_t Seed, typename F, typename... Args>
        CW_NOINLINE decltype(auto) dispatch(F&& function, Args&&... args) {
            constexpr uint32_t key = Seed | 1u;
            volatile uint32_t state = key;
            for (;;) {
                switch (static_cast<uint32_t>(state) ^ key) {
                    case 0: state = 1u ^ key; break;
                    case 1: state = (opaque_true<>() ? 2u : 3u) ^ key; break;
                    case 2:
                        CW_COMPILER_BARRIER();
                        return std::invoke(std::forward<F>(function), std::forward<Args>(args)...);
                    case 3: state = 2u ^ key; break;
                    default: throw std::logic_error("Cloakwork dispatcher state is invalid");
                }
            }
        }

        template<typename Func, uint32_t XK = static_cast<uint32_t>(CW_BUILD_SEED),
                 uint32_t S0 = 0, uint32_t S1 = 1, uint32_t S2 = 2, uint32_t S3 = 3,
                 uint32_t S4 = 4, uint32_t S5 = 5, uint32_t S6 = 6, uint32_t S7 = 7>
        class flattened_flow {
        public:
            template<typename... Args>
            decltype(auto) execute(Func func, Args&&... args) {
                return dispatch<XK>(
                    func, std::forward<Args>(args)...);
            }
        };

        template<typename T>
        CW_NOINLINE T indirect_branch(T value) {
            CW_COMPILER_BARRIER();
            return value;
        }
    }

    #define CW_IF(cond) \
        if(cloakwork::control_flow::opaque_true<>() && (cond))

    #define CW_ELSE \
        else if(cloakwork::control_flow::opaque_true<>())

    #define CW_FLATTEN(...) \
        cloakwork::control_flow::dispatch<CW_RANDOM_CT()>(__VA_ARGS__)

    //
    // Legacy state-derivation helpers retained for source compatibility.
    // CW_PROTECT dispatches a native callable; vm::program executes bytecode.

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

        //
        // opaque zero generators — produce 0 through mathematical identities
        // that static analysis cannot trivially resolve. used to entangle
        // dead block outputs with state transitions so DCE can't eliminate them.
        // CW_NOINLINE blocks cross-function constant folding.
        //
        namespace entangle {

            //
            // consecutive product parity: n*(n+1) is always even.
            // one of {n, n+1} must be even, so the product's LSB is always 0.
            //
            template<uint32_t Salt>
            static CW_NOINLINE uint32_t consec_product(uint32_t val) {
                volatile uint32_t n = val ^ Salt;
                CW_COMPILER_BARRIER();
                uint32_t v = n;
                volatile uint32_t prod = v * (v + 1u);
                CW_COMPILER_BARRIER();
                return static_cast<uint32_t>(prod) & 1u;
            }

            //
            // MBA sum identity: (a + b) == (a ^ b) + 2*(a & b).
            // subtracting both sides from the sum always yields zero.
            // three separate volatile stores prevent algebraic folding.
            //
            template<uint32_t Salt>
            static CW_NOINLINE uint32_t mba_sum(uint32_t val) {
                volatile uint32_t a = val ^ Salt;
                volatile uint32_t b = val ^ (Salt * 0x9E3779B9u);
                CW_COMPILER_BARRIER();
                uint32_t va = a, vb = b;
                volatile uint32_t sum = va + vb;
                volatile uint32_t xor_part = va ^ vb;
                volatile uint32_t carry = (va & vb) << 1;
                CW_COMPILER_BARRIER();
                return static_cast<uint32_t>(sum) -
                       static_cast<uint32_t>(xor_part) -
                       static_cast<uint32_t>(carry);
            }

            //
            // De Morgan identity: ~(a & b) == (~a | ~b).
            // XOR of both sides is always zero.
            //
            template<uint32_t Salt>
            static CW_NOINLINE uint32_t demorgan(uint32_t val) {
                volatile uint32_t a = val ^ Salt;
                volatile uint32_t b = val + Salt;
                CW_COMPILER_BARRIER();
                uint32_t va = a, vb = b;
                volatile uint32_t lhs = ~(va & vb);
                volatile uint32_t rhs = (~va) | (~vb);
                CW_COMPILER_BARRIER();
                return static_cast<uint32_t>(lhs) ^ static_cast<uint32_t>(rhs);
            }

            //
            // Gauss sum: iterative sum(0..n) == n*(n+1)/2 for all n.
            // computing both paths and XORing gives 0. the iterative
            // path produces a real loop that analysis must reason about.
            //
            template<uint32_t Salt>
            static CW_NOINLINE uint32_t gauss(uint32_t val) {
                volatile uint32_t n_raw = val ^ Salt;
                CW_COMPILER_BARRIER();
                uint32_t n = (static_cast<uint32_t>(n_raw) & 0xFu) + 2u;
                volatile uint32_t closed = (n * (n + 1u)) >> 1;
                CW_COMPILER_BARRIER();
                volatile uint32_t acc = 0;
                for (uint32_t i = 0; i <= n; ++i)
                    acc = static_cast<uint32_t>(acc) + i;
                CW_COMPILER_BARRIER();
                return static_cast<uint32_t>(closed) ^ static_cast<uint32_t>(acc);
            }

            //
            // dispatcher — selects identity variant at compile time.
            // returns 0 through the chosen path. the template params
            // ensure each call site gets a unique function instantiation.
            //
            template<uint32_t Variant, uint32_t Salt>
            static CW_NOINLINE uint32_t zero(uint32_t dead_output) {
                if constexpr ((Variant & 3u) == 0) return consec_product<Salt>(dead_output);
                else if constexpr ((Variant & 3u) == 1) return mba_sum<Salt>(dead_output);
                else if constexpr ((Variant & 3u) == 2) return demorgan<Salt>(dead_output);
                else return gauss<Salt>(dead_output);
            }
        }

        // noinline dispatch wrapper - prevents LTCG/WPO from seeing through
        // the flattened code and reconstructing the original CFG
        template<typename F>
        CW_NOINLINE auto execute(F&& f) -> decltype(f()) {
            CW_COMPILER_BARRIER();
            return std::forward<F>(f)();
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

    //
    // wraps arbitrary code in an encrypted state machine dispatcher.
    // the user's code becomes one state among dead blocks and opaque
    // predicates, producing decompiler-hostile output automatically.
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

    #define CW_PROTECT(ret_type, ...) \
        (cloakwork::control_flow::dispatch<CW_RANDOM_CT()>([&]() -> ret_type { __VA_ARGS__ }))

    #define CW_PROTECT_VOID(...) \
        (cloakwork::control_flow::dispatch<CW_RANDOM_CT()>([&]() { __VA_ARGS__ }))

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

    #define CW_PROTECT(ret_type, ...) \
        [&]() -> ret_type { __VA_ARGS__ }()

    #define CW_PROTECT_VOID(...) \
        [&]() { __VA_ARGS__ }()

#endif

#if CW_ENABLE_FUNCTION_OBFUSCATION

    template<typename Func>
    class obfuscated_call {
    private:
        using pointer = std::conditional_t<std::is_pointer_v<detail::clean_value_t<Func>>,
            detail::clean_value_t<Func>, std::add_pointer_t<Func>>;
        static_assert(std::is_function_v<std::remove_pointer_t<pointer>>, "CW_CALL requires a function or function pointer");
        // runtime-keyed function pointer encryption
        uint8_t encrypted_addr[sizeof(uintptr_t)];
        uint32_t pk0, pk1, pk2, pk3;

        // decoy array with randomized size and position
        static constexpr size_t MAX_DECOYS = 16;
        uintptr_t decoys[MAX_DECOYS];
        size_t decoy_count;
        size_t real_index;

        CW_FORCEINLINE void encrypt_ptr(pointer ptr) {
            uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
            memcpy(encrypted_addr, &addr, sizeof(uintptr_t));
            string_encrypt::cipher::rt_encrypt(encrypted_addr, sizeof(uintptr_t), pk0, pk1, pk2, pk3);
        }

        CW_FORCEINLINE pointer decrypt_ptr() const {
            uint8_t temp[sizeof(uintptr_t)];
            memcpy(temp, encrypted_addr, sizeof(uintptr_t));
            string_encrypt::cipher::rt_encrypt(temp, sizeof(uintptr_t), pk0, pk1, pk2, pk3);
            uintptr_t addr;
            memcpy(&addr, temp, sizeof(uintptr_t));
            return reinterpret_cast<pointer>(addr);
        }

    public:
        obfuscated_call(pointer func) {
            pk0 = static_cast<uint32_t>(CW_RANDOM_RT());
            pk1 = static_cast<uint32_t>(CW_RANDOM_RT());
            pk2 = static_cast<uint32_t>(CW_RANDOM_RT());
            pk3 = static_cast<uint32_t>(CW_RANDOM_RT());


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
        CW_FORCEINLINE decltype(auto) operator()(Args&&... args) const {
            static CW_ATOMIC(uint32_t) call_count{0};
            if ((++call_count % 100) == 0) {
                cloakwork::anti_debug::inline_check();
            }

            pointer real_func = decrypt_ptr();
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

        template<typename T, size_t Chunks = detail::default_scatter_chunks_v<T>>
        class scattered_value {
        private:
            static_assert(std::is_trivially_copyable_v<T>, "Scattered values must be trivially copyable");
            static_assert(Chunks > 1 && Chunks <= 64, "Chunks must be between 2 and 64");
            static_assert(sizeof(T) >= Chunks || Chunks == 2, "Too many chunks for type size");

            struct chunk_holder {
                std::unique_ptr<uint8_t[]> data;
                size_t size;
                uint8_t xor_key;

                chunk_holder() : size(0), xor_key(0) {}
                chunk_holder(chunk_holder&&) noexcept = default;
                chunk_holder& operator=(chunk_holder&&) noexcept = default;
                ~chunk_holder() { if (data) detail::wipe(data.get(), size); }
            };

            std::array<chunk_holder, Chunks> chunks;
            mutable CW_MUTEX mutex;

            void scatter_data(const T& value) {
                std::array<chunk_holder, Chunks> replacement;
                const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
                size_t bytes_per_chunk = sizeof(T) / Chunks;
                size_t remainder = sizeof(T) % Chunks;
                size_t byte_idx = 0;

                for(size_t i = 0; i < Chunks; ++i) {
                    size_t chunk_size = bytes_per_chunk + (i < remainder ? 1 : 0);
                    replacement[i].size = chunk_size;
                    replacement[i].data = std::make_unique<uint8_t[]>(chunk_size);
                    replacement[i].xor_key = static_cast<uint8_t>(CW_RANDOM_RT());

                    for(size_t j = 0; j < chunk_size && byte_idx < sizeof(T); ++j, ++byte_idx) {
                        replacement[i].data[j] = bytes[byte_idx] ^ replacement[i].xor_key;
                    }
                }
                chunks.swap(replacement);
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
                std::array<uint8_t, sizeof(T)> result{};
                uint8_t* result_bytes = result.data();
                size_t byte_idx = 0;

                for(size_t i = 0; i < Chunks; ++i) {
                    for(size_t j = 0; j < chunks[i].size && byte_idx < sizeof(T); ++j, ++byte_idx) {
                        result_bytes[byte_idx] = chunks[i].data[j] ^ chunks[i].xor_key;
                    }
                }

                T value = std::bit_cast<T>(result);
                detail::wipe(result.data(), result.size());
                return value;
            }

            CW_FORCEINLINE operator T() const { return get(); }

            CW_FORCEINLINE void set(const T& value) {
                CW_LOCK_GUARD(mutex);
                scatter_data(value);
            }
        };

        template<Arithmetic T>
        class polymorphic_value {
            mutable detail::encoded_storage<T> storage;
            mutable uint32_t access_count = 0;
            mutable CW_MUTEX mutex;
        public:
            polymorphic_value() = default;
            polymorphic_value(T value) : storage(value) {}
            polymorphic_value(const polymorphic_value& other) : storage(other.get()) {}
            polymorphic_value& operator=(const polymorphic_value& other) {
                if (this != &other) set(other.get());
                return *this;
            }
            T get() const {
                CW_LOCK_GUARD(mutex);
                T value = storage.get();
                if (++access_count % 100u == 0) storage.set(value);
                return value;
            }
            void set(T value) { CW_LOCK_GUARD(mutex); storage.set(value); }
            void rekey() { CW_LOCK_GUARD(mutex); storage.set(storage.get()); }
            operator T() const { return get(); }
            polymorphic_value& operator=(T value) { set(value); return *this; }
        };
    }
#else
    namespace data_hiding {
        template<typename T, size_t Chunks = detail::default_scatter_chunks_v<T>>
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
            Func* real_func;
#if defined(_WIN64) && !CW_KERNEL_MODE
            mutable std::shared_ptr<uint8_t> thunk;
            mutable std::mutex mutex;
            mutable uint32_t call_count = 0;
            static std::shared_ptr<uint8_t> make_thunk(Func* function) {
                return {thunk_gen::generate_thunk(reinterpret_cast<void*>(function)), thunk_gen::free_thunk};
            }
#endif
        public:
            metamorphic_function(std::initializer_list<Func*> funcs)
                : metamorphic_function(funcs.size() ? *funcs.begin() : nullptr) {}
            metamorphic_function(Func* function) : real_func(function) {
                if (!function) throw std::invalid_argument("Cloakwork requires a non-null function");
#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk = make_thunk(function);
#endif
            }
            metamorphic_function(const metamorphic_function&) = delete;
            metamorphic_function& operator=(const metamorphic_function&) = delete;
            metamorphic_function(metamorphic_function&& other) noexcept : real_func(other.real_func) {
#if defined(_WIN64) && !CW_KERNEL_MODE
                thunk = std::move(other.thunk);
#endif
            }
            template<typename... Args>
            decltype(auto) operator()(Args&&... args) const {
#if defined(_WIN64) && !CW_KERNEL_MODE
                std::shared_ptr<uint8_t> active;
                {
                    std::lock_guard<std::mutex> guard(mutex);
                    if (++call_count % 1000u == 0) {
                        auto replacement = make_thunk(real_func);
                        if (replacement) thunk = std::move(replacement);
                    }
                    active = thunk;
                }
                if (active) return reinterpret_cast<Func*>(active.get())(std::forward<Args>(args)...);
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

        CW_FORCEINLINE void* getProcAddress(void* module, uint32_t funcHash);

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
            CW_FORCEINLINE void* resolve_forwarded_export(const char* forward_str, size_t max_len) {
                if (!forward_str || max_len == 0) return nullptr;

                size_t dot_pos = max_len;
                size_t end_pos = max_len;
                for (size_t i = 0; i < max_len; ++i) {
                    char c = forward_str[i];
                    if (c == '.' && dot_pos == max_len) dot_pos = i;
                    if (c == '\0') {
                        end_pos = i;
                        break;
                    }
                }

                if (dot_pos == max_len || end_pos == max_len || dot_pos == 0 || dot_pos + 1 >= end_pos)
                    return nullptr;

                char module_name[256];
                if (dot_pos >= sizeof(module_name) - 5) return nullptr;

                for (size_t i = 0; i < dot_pos; ++i)
                    module_name[i] = forward_str[i];
                module_name[dot_pos] = '.';
                module_name[dot_pos + 1] = 'd';
                module_name[dot_pos + 2] = 'l';
                module_name[dot_pos + 3] = 'l';
                module_name[dot_pos + 4] = '\0';

                const char* func_name = forward_str + dot_pos + 1;

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

                return getProcAddress(target_mod, func_hash);
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
                        return detail::resolve_forwarded_export(
                            forward_str,
                            static_cast<size_t>(export_end - static_cast<uint64_t>(func_rva)));
#endif
                    }

                    if (!detail::rva_in_bounds(func_rva, 1, image_size)) return nullptr;
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
            static CW_ATOMIC(uintptr_t) cached{0};
            uintptr_t val = cached.load(CW_MO_ACQUIRE);
            if (!val) {
                void* mod = getModuleBase(ModuleHash);
                if (mod) {
                    val = reinterpret_cast<uintptr_t>(getProcAddress(mod, FuncHash));
                    if (val) cached.store(val, CW_MO_RELEASE);
                }
            }
            return reinterpret_cast<void*>(val);
        }
    }

    #define CW_IMPORT(mod, func) \
        reinterpret_cast<decltype(&func)>( \
            cloakwork::imports::getCachedImport<CW_HASH_CI(mod), CW_HASH(#func)>())

    #define CW_IMPORT_WIDE(mod, func) \
        reinterpret_cast<decltype(&func)>( \
            cloakwork::imports::getCachedImport<CW_HASH_WIDE_CI(mod), CW_HASH(#func)>())
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
            static CW_ATOMIC(uint32_t) cached{SYSCALL_ERROR};
            uint32_t val = cached.load(CW_MO_ACQUIRE);
            if (val == SYSCALL_ERROR) {
                val = getSyscallNumber(FuncHash);
                if (val != SYSCALL_ERROR) cached.store(val, CW_MO_RELEASE);
            }
            return val;
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
            static CW_ATOMIC(uintptr_t) gadget{0};
            uintptr_t val = gadget.load(CW_MO_ACQUIRE);
            if (!val) {
                val = reinterpret_cast<uintptr_t>(findSyscallGadget());
                if (val) gadget.store(val, CW_MO_RELEASE);
            }
            return reinterpret_cast<void*>(val);
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

            static thread_local uint8_t* thunk = nullptr;

            if (!thunk) {
                thunk = reinterpret_cast<uint8_t*>(
                    VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (!thunk) return static_cast<NTSTATUS>(0xC0000001);

                // mov r10, rcx; mov eax, imm32; jmp [rip+0]; dq gadget
                thunk[0] = 0x4C; thunk[1] = 0x8B; thunk[2] = 0xD1;
                thunk[3] = 0xB8;
                thunk[8] = 0xFF; thunk[9] = 0x25; thunk[10] = 0x00; thunk[11] = 0x00;
                thunk[12] = 0x00; thunk[13] = 0x00;
            }

            DWORD old_protect = 0;
            if (!VirtualProtect(thunk, 32, PAGE_READWRITE, &old_protect))
                return static_cast<NTSTATUS>(0xC0000001);

            uint64_t gadget_bits = reinterpret_cast<uint64_t>(gadget);
            memcpy(thunk + 4, &number, sizeof(number));
            memcpy(thunk + 14, &gadget_bits, sizeof(gadget_bits));

            DWORD execute_protect = 0;
            if (!VirtualProtect(thunk, 32, PAGE_EXECUTE_READ, &execute_protect))
                return static_cast<NTSTATUS>(0xC0000001);
            FlushInstructionCache(GetCurrentProcess(), thunk, 32);
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
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_equals(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a == b;
        }
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_not_equals(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a != b;
        }
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_less(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a < b;
        }
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_greater(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a > b;
        }
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_less_equal(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a <= b;
        }
        template<typename A, typename B>
        CW_NOINLINE bool obfuscated_greater_equal(const A& a, const B& b) {
            CW_COMPILER_BARRIER();
            return a >= b;
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

#if !CW_KERNEL_MODE
    // Explicit integer bytecode. Native C++ bodies passed to CW_PROTECT are not
    // translated into these instructions. Programs are immutable and shareable.
    namespace vm {
        enum class opcode : uint8_t {
            constant, argument, move, add, sub, mul, bit_and, bit_or, bit_xor,
            rotate_left, less, jump, jump_zero, ret
        };
        struct instruction {
            opcode op;
            uint8_t dst = 0, a = 0, b = 0;
            uint64_t immediate = 0;
        };
        enum class error { none, missing_argument, invalid_instruction, step_limit };
        struct result {
            uint64_t value = 0;
            error status = error::none;
            size_t steps = 0;
            explicit operator bool() const noexcept { return status == error::none; }
        };

        namespace detail {
            constexpr uint64_t mix(uint64_t x) {
                x ^= x >> 30;
                x *= 0xbf58476d1ce4e5b9ULL;
                x ^= x >> 27;
                x *= 0x94d049bb133111ebULL;
                return x ^ (x >> 31);
            }
            constexpr uint8_t inverse_byte(uint8_t odd) {
                unsigned inverse = 1;
                for (int i = 0; i < 3; ++i) inverse *= 2u - odd * inverse;
                return static_cast<uint8_t>(inverse);
            }
        }

        template<size_t N, size_t Registers = 8, uint64_t Seed = CW_BUILD_SEED>
        class program {
            static_assert(N > 0, "A VM program cannot be empty");
            static_assert(Registers > 0 && Registers <= 256 && (Registers & (Registers - 1)) == 0,
                          "Register count must be a power of two from 1 to 256");
            std::array<uint64_t, N * 2> code{};
            static constexpr uint8_t multiplier = static_cast<uint8_t>(Seed | 1u);
            static constexpr uint8_t bias = static_cast<uint8_t>(Seed >> 8);
            static constexpr size_t reg(size_t index) {
                return (index * multiplier + bias) & (Registers - 1);
            }
            static constexpr uint64_t mask(size_t index) {
                return detail::mix(Seed + (index + 1) * 0x9e3779b97f4a7c15ULL);
            }
            static constexpr bool valid(const instruction& i) {
                if (static_cast<unsigned>(i.op) > static_cast<unsigned>(opcode::ret)) return false;
                // Require every register field to be valid, including unused fields.
                if (i.dst >= Registers || i.a >= Registers || i.b >= Registers) return false;
                if ((i.op == opcode::jump || i.op == opcode::jump_zero) && i.immediate >= N) return false;
                return true;
            }
        public:
            consteval explicit program(const std::array<instruction, N>& input) {
                bool has_return = false;
                for (size_t pc = 0; pc < N; ++pc) {
                    const auto& i = input[pc];
                    if (!valid(i)) throw "Invalid Cloakwork VM instruction";
                    has_return |= i.op == opcode::ret;
                    const auto encoded_op = static_cast<uint8_t>(static_cast<uint8_t>(i.op) * multiplier + bias);
                    const uint64_t packed = encoded_op | (uint64_t{i.dst} << 8) |
                        (uint64_t{i.a} << 16) | (uint64_t{i.b} << 24);
                    code[pc * 2] = packed ^ mask(pc * 2);
                    code[pc * 2 + 1] = i.immediate ^ mask(pc * 2 + 1);
                }
                if (!has_return) throw "A Cloakwork VM program needs a return instruction";
            }

            // Arithmetic wraps modulo 2^64. Register reads before writes yield zero.
            // The step budget counts fetched instructions, including return.
            CW_NOINLINE result run(std::span<const uint64_t> arguments = {}, size_t budget = 100000) const {
                std::array<uint64_t, Registers> registers{};
                struct wipe_registers {
                    std::array<uint64_t, Registers>& data;
                    ~wipe_registers() { cloakwork::detail::wipe(data.data(), sizeof(data)); }
                } cleanup{registers};
                size_t pc = 0;
                const volatile uint64_t* source = code.data();
                for (size_t steps = 0; steps < budget; ++steps) {
                    if (pc >= N) return {0, error::invalid_instruction, steps};
                    const uint64_t packed = source[pc * 2] ^ mask(pc * 2);
                    const uint64_t immediate = source[pc * 2 + 1] ^ mask(pc * 2 + 1);
                    const auto decoded = static_cast<uint8_t>((static_cast<uint8_t>(packed) - bias) *
                        detail::inverse_byte(multiplier));
                    instruction i{static_cast<opcode>(decoded), static_cast<uint8_t>(packed >> 8),
                        static_cast<uint8_t>(packed >> 16), static_cast<uint8_t>(packed >> 24), immediate};
                    if ((packed >> 32) != 0 || !valid(i)) return {0, error::invalid_instruction, steps + 1};
                    auto& dst = registers[reg(i.dst)];
                    const uint64_t a = registers[reg(i.a)], b = registers[reg(i.b)];
                    ++pc;
                    switch (i.op) {
                        case opcode::constant: dst = immediate; break;
                        case opcode::argument:
                            if (immediate >= arguments.size()) return {0, error::missing_argument, steps + 1};
                            dst = arguments[static_cast<size_t>(immediate)]; break;
                        case opcode::move: dst = a; break;
                        case opcode::add:
#if CW_ENABLE_VALUE_OBFUSCATION
                            dst = mba::add_mba<uint64_t, static_cast<int>(Seed & 7u)>(a, b);
#else
                            dst = a + b;
#endif
                            break;
                        case opcode::sub: dst = a - b; break;
                        case opcode::mul: dst = a * b; break;
                        case opcode::bit_and: dst = a & b; break;
                        case opcode::bit_or: dst = a | b; break;
                        case opcode::bit_xor: dst = a ^ b; break;
                        case opcode::rotate_left: dst = std::rotl(a, static_cast<int>(b & 63u)); break;
                        case opcode::less: dst = a < b; break;
                        case opcode::jump: pc = static_cast<size_t>(immediate); break;
                        case opcode::jump_zero: if (a == 0) pc = static_cast<size_t>(immediate); break;
                        case opcode::ret: return {a, error::none, steps + 1};
                    }
                    CW_COMPILER_BARRIER();
                }
                return {0, error::step_limit, budget};
            }
        };

        template<uint64_t Seed = CW_BUILD_SEED, size_t Registers = 8, size_t N>
        consteval auto make_program(const std::array<instruction, N>& input) {
            return program<N, Registers, Seed>{input};
        }
    }
#endif

    namespace constants {

        template<typename T, T Value, uint8_t Key = static_cast<uint8_t>(CW_DETAIL_RAND_CT(1, 255))>
        struct encrypted_constant {
            // store encrypted value as a non-constexpr static to prevent the compiler
            // from seeing both the encrypted value and key in the same compile-time context,
            // which would let LTCG constant-fold the XOR back to the original value
            static inline volatile T stored_encrypted = [] {
                if constexpr (std::is_integral_v<T>) return static_cast<T>(Value ^ static_cast<T>(Key));
                else return Value;
            }();

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

        //
        // Junk that looks like a hash table probe or string comparison.
        // Touches the stack in patterns typical of real hash functions,
        // with buffer init + accumulation + conditional store.
        //
        template<int N = CW_DETAIL_RAND_CT(1, 1000)>
        CW_NOINLINE void junk_computation() {
            volatile uint32_t state = static_cast<uint32_t>(N);
            volatile uint8_t buf[16];
            CW_COMPILER_BARRIER();

            // init buffer -- looks like setting up a key or small payload
            for (int i = 0; i < 16; ++i)
                buf[i] = static_cast<uint8_t>((state >> (i & 3)) ^ i);

            // accumulate -- FNV-like hash over the buffer
            volatile uint32_t h = state ^ 0x811C9DC5u;
            for (int i = 0; i < 16; ++i) {
                h ^= buf[i];
                h *= 0x01000193u;
            }
            CW_COMPILER_BARRIER();

            // conditional store -- common pattern in real lookup code
            if ((h & 0xFu) > 7u)
                buf[0] = static_cast<uint8_t>(h >> 24);

            CW_COMPILER_BARRIER();
        }

        //
        // Junk that mimics a retry loop with exponential backoff.
        // Common real-world pattern for lock acquisition or network retry.
        //
        template<int N = CW_DETAIL_RAND_CT(1, 1000)>
        CW_NOINLINE void junk_control_flow() {
            volatile uint32_t attempts = 0;
            volatile uint32_t backoff = static_cast<uint32_t>(N) & 0x3u;
            CW_COMPILER_BARRIER();

            while (attempts < 3u) {
                volatile uint32_t result = (attempts * 0x45D9F3Bu) ^ backoff;
                CW_COMPILER_BARRIER();

                if (result & 0x8000u) {
                    break; // "success" path
                }
                backoff = (backoff << 1) | 1u;
                ++attempts;
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
                        if (base[sec_start + j] == 0xC3)
                            return base + sec_start + j;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return nullptr;
            }
#endif
            return nullptr;
        }

        //
        // Find a "jmp rbx" (FF E3) gadget in ntdll. This gives us a trampoline
        // that makes the actual call appear to originate from within ntdll.
        // The call chain becomes: our_code -> ntdll!<jmp_rbx> -> target_func
        //
        CW_FORCEINLINE void* findJmpRbxGadget() {
#if defined(_WIN64) && !CW_KERNEL_MODE
            __try {
                void* ntdll = imports::getModuleBase(CW_HASH_CI("ntdll.dll"));
                if (!ntdll) return nullptr;

                IMAGE_NT_HEADERS* nt = nullptr;
                uint32_t image_size = 0;
                if (!imports::detail::validate_pe_header(ntdll, &nt, &image_size))
                    return nullptr;

                auto base = reinterpret_cast<uint8_t*>(ntdll);
                auto section = IMAGE_FIRST_SECTION(nt);
                for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
                    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                    uint32_t start = section->VirtualAddress;
                    uint32_t size = section->Misc.VirtualSize;
                    if (!imports::detail::rva_in_bounds(start, size, image_size)) continue;

                    for (uint32_t j = 0; j + 1 < size; ++j) {
                        uint8_t* p = base + start + j;
                        if (p[0] == 0xFF && p[1] == 0xE3) // jmp rbx
                            return p;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
            return nullptr;
        }

        CW_FORCEINLINE void* getRetGadget() {
            static void* gadget = nullptr;
            if (!gadget) gadget = findRetGadget();
            return gadget;
        }

        CW_FORCEINLINE void* getJmpRbxGadget() {
            static void* gadget = nullptr;
            if (!gadget) gadget = findJmpRbxGadget();
            return gadget;
        }

        //
        // Return address spoofing via gadget chain.
        //
        // We overwrite our return address with a "ret" gadget in ntdll so
        // the callee's stack frame shows ntdll as the caller. The jmp_rbx
        // gadget is stored for potential future use as a full trampoline
        // (which would require an executable thunk page).
        //
        // Stack layout we create before calling the target:
        //   [rsp+0] = ret_gadget  (fake return addr seen by callee)
        //   real_return saved in local, restored after callee returns
        //
        template<typename Ret, typename... Args>
        class spoofed_call {
        private:
            using FuncPtr = Ret(*)(Args...);
            FuncPtr func;
            void* ret_gadget;
            void* jmp_gadget;

        public:
            spoofed_call(FuncPtr f)
                : func(f)
                , ret_gadget(getRetGadget())
                , jmp_gadget(getJmpRbxGadget()) {}

            CW_NOINLINE Ret operator()(Args... args) {
#if defined(_WIN64)
                if (ret_gadget) {
                    void** ret_ptr = reinterpret_cast<void**>(_AddressOfReturnAddress());
                    void* real_return = *ret_ptr;

                    // overwrite our return address so the callee sees ntdll
                    *ret_ptr = ret_gadget;
                    CW_COMPILER_BARRIER();

                    if constexpr (std::is_void_v<Ret>) {
                        func(args...);
                        *ret_ptr = real_return;
                    } else {
                        Ret result = func(args...);
                        *ret_ptr = real_return;
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
                    if (status == 0) {
                        if (debug_object) CloseHandle(debug_object);
                        return true;  // STATUS_SUCCESS means debug object exists
                    }

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
        #define CW_INT(x) (cloakwork::obfuscated_value<cloakwork::detail::clean_value_t<decltype(x)>>{x})
        #define CW_MBA(x) (cloakwork::mba_obfuscated<cloakwork::detail::clean_value_t<decltype(x)>>{x})

        // obfuscated XOR using MBA while capturing operands once.
        #define CW_XOR(a, b) (cloakwork::mba::xor_mba_once((a), (b)))
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
        #define CW_SCATTER(x) (cloakwork::data_hiding::scattered_value<cloakwork::detail::clean_value_t<decltype(x)>>{x})
        #define CW_POLY(x) (cloakwork::data_hiding::polymorphic_value<cloakwork::detail::clean_value_t<decltype(x)>>{x})
    #else
        #define CW_SCATTER(x) (x)
        #define CW_POLY(x) (x)
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

        static BOOL WINAPI stub_is_debugger_present() {
            return FALSE;
        }

        static BOOL WINAPI stub_check_remote_debugger_present(HANDLE, PBOOL present) {
            if (present) *present = FALSE;
            return TRUE;
        }

        static void WINAPI stub_output_debug_string_a(LPCSTR) {}
        static void WINAPI stub_output_debug_string_w(LPCWSTR) {}

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
                    if (import_desc->OriginalFirstThunk == 0 || import_desc->FirstThunk == 0)
                        continue;

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
                            ULONG_PTR replacement = 0;
                            if (name_hash == CW_HASH("IsDebuggerPresent")) {
                                replacement = reinterpret_cast<ULONG_PTR>(&stub_is_debugger_present);
                            } else if (name_hash == CW_HASH("CheckRemoteDebuggerPresent")) {
                                replacement = reinterpret_cast<ULONG_PTR>(&stub_check_remote_debugger_present);
                            } else if (name_hash == CW_HASH("OutputDebugStringA")) {
                                replacement = reinterpret_cast<ULONG_PTR>(&stub_output_debug_string_a);
                            } else if (name_hash == CW_HASH("OutputDebugStringW")) {
                                replacement = reinterpret_cast<ULONG_PTR>(&stub_output_debug_string_w);
                            }

                            if (name_hash == h && replacement) {
                                DWORD old_protect;
                                if (VirtualProtect(&func_ref->u1.Function,
                                    sizeof(func_ref->u1.Function),
                                    PAGE_READWRITE, &old_protect)) {
                                    func_ref->u1.Function = replacement;
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
#else
    #define CW_HIDE_THREAD() ((void)0)
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
    #define CW_CHECK_DEBUG()             (cloakwork::anti_debug::comprehensive_check())
#else
    #define CW_CHECK_DEBUG()             (false)
#endif

#if CW_ENABLE_IMPORT_HIDING
    #define CW_GET_MODULE(name)          (cloakwork::imports::getModuleBase(CW_HASH_CI(name)))
    #define CW_GET_PROC(mod, func)       (cloakwork::imports::getProcAddress(mod, CW_HASH(func)))
#else
    #define CW_GET_MODULE(name)          (nullptr)
    #define CW_GET_PROC(mod, func)       (nullptr)
#endif

    #define CW_HASH_RT(str)              (cloakwork::hash::fnv1a_runtime(str))
    #define CW_HASH_RT_CI(str)           (cloakwork::hash::fnv1a_runtime_ci(str))

#if CW_ENABLE_INTEGRITY_CHECKS
    #define CW_COMPUTE_HASH(ptr, size)   (cloakwork::integrity::computeHash(ptr, size))
    #define CW_VERIFY_FUNCS(...)         (cloakwork::integrity::verifyFunctions(__VA_ARGS__))
#else
    #define CW_COMPUTE_HASH(ptr, size)   (0u)
    #define CW_VERIFY_FUNCS(...)         (true)
#endif

    #define CW_RET_GADGET()              (cloakwork::spoof::getRetGadget())

    // MBA negation (completes CW_ADD / CW_SUB / CW_AND / CW_OR set)
#if CW_ENABLE_VALUE_OBFUSCATION
    #define CW_NEG(a)                    (cloakwork::mba::neg_mba<decltype(+(a))>((a)))
#else
    #define CW_NEG(a)                    (-(a))
#endif

} // namespace cloakwork

#ifdef _MSC_VER
    #pragma warning(pop)
#endif

#ifdef __clang__
    #pragma clang diagnostic pop
#endif

#endif // CLOAKWORK_H
