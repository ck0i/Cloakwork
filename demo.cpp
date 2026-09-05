/*++

This demo exercises the public Cloakwork APIs
in one translation unit.

--*/

#include <iostream>
#include <string>
#include "cloakwork.h"

// simple function to demonstrate function pointer obfuscation
int simple_add(int a, int b) {
    return a + b;
}

// alternate implementation for metamorphic demo
int simple_add_v2(int a, int b) {
    return (a + b);
}

// function to demonstrate flattening
int calculate_something(int value) {
    return value * 2 + 10;
}

// demonstrates scattered data storage
struct secret_data {
    int user_id;
    int access_level;
    int session_token;
};

int main() {
    // CW_SCRUB_DEBUG_IMPORTS() modifies the process IAT; invoke it explicitly if needed.

    std::cout << CW_STR("=== CLOAKWORK COMPREHENSIVE DEMO ===") << std::endl;
    std::cout << CW_STR("demonstrating obfuscation, encryption, and anti-debug features") << std::endl;
    std::cout << CW_STR("NOTE: crash-on-debug features disabled for demo (shows detections without crashing)") << std::endl << std::endl;

    // ==================================================================
    // 1. BASIC STRING ENCRYPTION (compile-time + runtime)
    // ==================================================================
    std::cout << CW_STR("[1] String Encryption Demo") << std::endl;

    // strings use compile-time keys derived from the shared build seed
    const char* encrypted_msg = CW_STR("this string is encrypted at compile-time!");
    std::cout << CW_STR("   encrypted: ") << encrypted_msg << std::endl;

    const char* another_msg = CW_STR("each execution has different runtime keys");
    std::cout << CW_STR("   runtime entropy: ") << another_msg << std::endl << std::endl;

    // ==================================================================
    // 2. ENHANCED STRING ENCRYPTION (multi-layer + stack-based)
    // ==================================================================
    std::cout << CW_STR("[2] Enhanced String Encryption Demo") << std::endl;

    // two encoding passes, with a stable plaintext cache after first access
    const char* layered_msg = CW_STR_LAYERED("two-pass encoded string with stable pointer lifetime");
    std::cout << CW_STR("   layered encryption: ") << layered_msg << std::endl;

    // stack-based encrypted string (auto-clears on scope exit)
    {
        auto stack_msg = CW_STR_STACK("this string auto-clears when leaving scope");
        std::cout << CW_STR("   stack-based encryption: ") << stack_msg.get() << std::endl;
        std::cout << CW_STR("   (owned buffer will be zeroed on scope exit)") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 3. ANTI-DEBUG PROTECTION
    // ==================================================================
    std::cout << CW_STR("[3] Anti-Debug Protection Demo") << std::endl;
    std::cout << CW_STR("   checking for debuggers and analysis tools...") << std::endl;

    // use namespace functions for granular checks
    bool any_detected = false;

    if (cloakwork::anti_debug::is_debugger_present()) {
        std::cout << CW_STR("   WARNING: basic debugger detected!") << std::endl;
        any_detected = true;
    } else {
        std::cout << CW_STR("   basic debugger check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::has_hardware_breakpoints()) {
        std::cout << CW_STR("   WARNING: hardware breakpoints detected!") << std::endl;
        any_detected = true;
    } else {
        std::cout << CW_STR("   hardware breakpoint check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::advanced::detect_hiding_tools()) {
        std::cout << CW_STR("   WARNING: anti-anti-debug tools detected!") << std::endl;
        any_detected = true;
    } else {
        std::cout << CW_STR("   hiding tools check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::advanced::suspicious_parent_process()) {
        std::cout << CW_STR("   WARNING: suspicious parent process!") << std::endl;
        any_detected = true;
    } else {
        std::cout << CW_STR("   parent process check: clean") << std::endl;
    }

    // note: CW_ANTI_DEBUG() would crash if debugger detected (commented out for demo)
    // CW_ANTI_DEBUG();

    if (any_detected) {
        std::cout << CW_STR("   NOTE: in production, CW_ANTI_DEBUG() would crash here") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 4. VALUE OBFUSCATION
    // ==================================================================
    std::cout << CW_STR("[4] Value Obfuscation Demo") << std::endl;

    // obfuscated integer - stored with xor/rotation/addition layers
    auto obfuscated_number = CW_INT(42);
    std::cout << CW_STR("   obfuscated value (multi-layer): ") << obfuscated_number.get() << std::endl;

    // MBA (mixed boolean arithmetic) obfuscation
    auto mba_number = CW_MBA(1337);
    std::cout << CW_STR("   MBA obfuscated value: ") << mba_number.get() << std::endl;

    // polymorphic value - mutates internal representation
    auto poly_value = CW_POLY(12345);
    std::cout << CW_STR("   polymorphic value: ") << static_cast<int>(poly_value) << std::endl;

    // scattered across allocations; memory inspection can still recover it
    secret_data my_data = { 1001, 5, static_cast<int>(0xDEADBEEF) };
    auto scattered = CW_SCATTER(my_data);
    secret_data retrieved = scattered.get();
    std::cout << CW_STR("   scattered data recovered - user_id: ") << retrieved.user_id << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 5. BOOLEAN OBFUSCATION DEMO
    // ==================================================================
    std::cout << CW_STR("[5] Boolean Obfuscation Demo") << std::endl;

    // CW_TRUE and CW_FALSE - obfuscated constants using opaque predicates
    std::cout << CW_STR("   testing CW_TRUE: ");
    if (CW_TRUE) {
        std::cout << CW_STR("always executes (correct)") << std::endl;
    } else {
        std::cout << CW_STR("ERROR - should not happen") << std::endl;
    }

    std::cout << CW_STR("   testing CW_FALSE: ");
    if (CW_FALSE) {
        std::cout << CW_STR("ERROR - should not happen") << std::endl;
    } else {
        std::cout << CW_STR("never executes true branch (correct)") << std::endl;
    }

    // CW_BOOL - obfuscate boolean expressions
    int test_x = 50;
    int test_y = 100;
    bool obf_result = CW_BOOL(test_x < test_y);
    std::cout << CW_STR("   CW_BOOL(50 < 100) = ") << (obf_result ? CW_STR("true") : CW_STR("false")) << CW_STR(" (expected: true)") << std::endl;

    bool obf_result2 = CW_BOOL(test_x > test_y);
    std::cout << CW_STR("   CW_BOOL(50 > 100) = ") << (obf_result2 ? CW_STR("true") : CW_STR("false")) << CW_STR(" (expected: false)") << std::endl;

    // obfuscated_bool class for persistent storage
    cloakwork::obf_bool license_flag(true);
    std::cout << CW_STR("   obfuscated_bool(true).get() = ") << (license_flag.get() ? CW_STR("true") : CW_STR("false")) << std::endl;

    license_flag = false;
    std::cout << CW_STR("   after setting to false: ") << (license_flag.get() ? CW_STR("true") : CW_STR("false")) << std::endl;

    // demonstrate logical operators
    cloakwork::obf_bool flag_a(true);
    cloakwork::obf_bool flag_b(false);
    std::cout << CW_STR("   !obfuscated_bool(true) = ") << ((!flag_a).get() ? CW_STR("true") : CW_STR("false")) << CW_STR(" (expected: false)") << std::endl;
    std::cout << CW_STR("   obfuscated_bool(true) && false = ") << ((flag_a && false).get() ? CW_STR("true") : CW_STR("false")) << CW_STR(" (expected: false)") << std::endl;
    std::cout << CW_STR("   obfuscated_bool(false) || true = ") << ((flag_b || true).get() ? CW_STR("true") : CW_STR("false")) << CW_STR(" (expected: true)") << std::endl;

    std::cout << CW_STR("   (booleans stored as multi-byte patterns, not simple 0/1)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 6. MIXED BOOLEAN ARITHMETIC (MBA) DEMO
    // ==================================================================
    std::cout << CW_STR("[6] Mixed Boolean Arithmetic Demo") << std::endl;

    // demonstrate MBA transformations (normally hidden inside obfuscation)
    int val1 = 100;
    int val2 = 50;

    // MBA addition: (x ^ y) + 2 * (x & y)
    int mba_add_result = CW_ADD(val1, val2);
    std::cout << CW_STR("   MBA add(100, 50) = ") << mba_add_result << CW_STR(" (expected: 150)") << std::endl;

    // MBA subtraction: (x ^ y) - 2 * (~x & y)
    int mba_sub_result = CW_SUB(val1, val2);
    std::cout << CW_STR("   MBA sub(100, 50) = ") << mba_sub_result << CW_STR(" (expected: 50)") << std::endl;

    // MBA negation: ~x + 1
    int mba_neg_result = CW_NEG(42);
    std::cout << CW_STR("   MBA neg(42) = ") << mba_neg_result << CW_STR(" (expected: -42)") << std::endl;

    std::cout << CW_STR("   (these transformations hide arithmetic from static analysis)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 7. CONTROL FLOW OBFUSCATION
    // ==================================================================
    std::cout << CW_STR("[7] Control Flow Obfuscation Demo") << std::endl;

    auto test_value_obf = CW_INT(100);
    int test_value = test_value_obf.get();

    // obfuscated if/else with opaque predicates
    CW_IF(test_value > 50) {
        std::cout << CW_STR("   obfuscated if: value is greater than 50") << std::endl;
    } CW_ELSE {
        std::cout << CW_STR("   obfuscated else: this shouldn't execute") << std::endl;
    }

    // obfuscated branching
    CW_BRANCH(test_value == 100) {
        std::cout << CW_STR("   obfuscated branch: value equals 100") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 8. CONTROL FLOW FLATTENING (function wrapper)
    // ==================================================================
    std::cout << CW_STR("[8] Control Flow Flattening Demo (function wrapper)") << std::endl;

    // flatten the control flow via state machine
    auto flattened_result = CW_FLATTEN(calculate_something, 15);
    std::cout << CW_STR("   CW_FLATTEN result: ") << flattened_result << std::endl;
    std::cout << CW_STR("   (wraps function call in switch-based state machine)") << std::endl;

    std::cout << std::endl;
    // ==================================================================
    // 8b. CFG PROTECTION (CW_PROTECT)
    // ==================================================================
    std::cout << CW_STR("[8b] CFG Protection Demo (CW_PROTECT)") << std::endl;
    std::cout << CW_STR("   wrapping code in encrypted state machine dispatchers...") << std::endl;

    int cfg_input = 15;

    // conditional protected by encrypted state machine
    int prot_result1 = CW_PROTECT(int, {
        if (cfg_input > 20) return cfg_input * 3;
        return cfg_input + 100;
    });
    std::cout << CW_STR("   conditional: if(15>20) 15*3 else 15+100 = ") << prot_result1
              << CW_STR(" (expected: 115)") << std::endl;

    // loop protected by encrypted state machine
    int prot_result2 = CW_PROTECT(int, {
        int x = cfg_input * 2;
        int acc = 0;
        while (x > 0) {
            acc += x;
            x -= 3;
        }
        return acc;
    });
    std::cout << CW_STR("   loop: sum(30,27,...,3) = ") << prot_result2
              << CW_STR(" (expected: 165)") << std::endl;

    // same void side-effect as demo 4
    int prot_side = 0;
    CW_PROTECT_VOID({
        for (int i = 5; i > 0; i--)
            prot_side += i;
    });
    std::cout << CW_STR("   void: sum(5..1) side_effect = ") << prot_side
              << CW_STR(" (expected: 15)") << std::endl;

    std::cout << CW_STR("   (encrypted state machine output, zero manual decomposition)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 9. FUNCTION POINTER OBFUSCATION
    // ==================================================================
    std::cout << CW_STR("[9] Function Pointer Obfuscation Demo") << std::endl;

    // obfuscate function pointer with anti-debug checks
    auto obfuscated_func = CW_CALL(simple_add);
    int func_result = obfuscated_func(15, 27);
    std::cout << CW_STR("   obfuscated function call result: ") << func_result << std::endl;
    std::cout << CW_STR("   (function pointer is encrypted and includes anti-debug)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 10. METAMORPHIC FUNCTION DEMO
    // ==================================================================
    std::cout << CW_STR("[10] Metamorphic Function Demo") << std::endl;

    // create metamorphic function that switches between implementations
    cloakwork::meta_func<int(int, int)> meta_add({simple_add, simple_add_v2});

    std::cout << CW_STR("   calling metamorphic function 5 times:") << std::endl;
    for (int i = 0; i < 5; i++) {
        int result = meta_add(10, 20);
        std::cout << CW_STR("     call ") << (i+1) << CW_STR(": result = ") << result << std::endl;
    }
    std::cout << CW_STR("   (implementation switches between calls, confuses analysis)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 11. COMPREHENSIVE PROTECTION DEMO
    // ==================================================================
    std::cout << CW_STR("[11] Comprehensive Protection Demo") << std::endl;
    std::cout << CW_STR("    combining multiple protection layers...") << std::endl;

    // protected "secret" calculation with all layers
    auto secret_key_obf = CW_MBA(0x1337);  // MBA obfuscated value
    int secret_key = secret_key_obf.get();

    CW_IF(secret_key != 0) {
        // note: CW_ANTI_DEBUG() would crash if debugger detected (commented for demo)
        // CW_ANTI_DEBUG();

        // transform the key using obfuscated operations
        auto xor_part = CW_INT(secret_key ^ 0xDEAD);
        auto add_part = CW_MBA(0xBEEF);
        int transformed_key = xor_part.get() + add_part.get();

        std::cout << "    " << CW_STR_LAYERED("protected computation result: ") << transformed_key << std::endl;
        std::cout << "    " << CW_STR_LAYERED("(CW_ANTI_DEBUG would protect this in production)") << std::endl;
    } CW_ELSE {
        std::cout << "    " << CW_STR("unexpected code path") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 12. ADVANCED ANTI-DEBUG SHOWCASE
    // ==================================================================
    std::cout << CW_STR("[12] Advanced Anti-Debug Techniques") << std::endl;
    std::cout << CW_STR("    running comprehensive analysis detection...") << std::endl;

    // use namespace functions for granular checks
    if (cloakwork::anti_debug::advanced::kernel_debugger_present()) {
        std::cout << CW_STR("    ALERT: kernel debugger detected!") << std::endl;
    } else {
        std::cout << CW_STR("    kernel debugger: not detected") << std::endl;
    }

    // timing check can have false positives
    if (cloakwork::anti_debug::advanced::advanced_timing_check()) {
        std::cout << CW_STR("    INFO: timing discrepancy detected (may be false positive)") << std::endl;
    } else {
        std::cout << CW_STR("    timing analysis: clean") << std::endl;
    }

    if (cloakwork::anti_debug::advanced::detect_debugger_artifacts()) {
        std::cout << CW_STR("    INFO: debugger artifacts found in registry") << std::endl;
    } else {
        std::cout << CW_STR("    registry artifacts: clean") << std::endl;
    }

    // comprehensive check via macro
    if (CW_CHECK_DEBUG()) {
        std::cout << CW_STR("    COMPREHENSIVE: debugger detected (CW_ANTI_DEBUG would crash)") << std::endl;
    } else {
        std::cout << CW_STR("    COMPREHENSIVE: all checks passed") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 13. WIDE STRING ENCRYPTION
    // ==================================================================
    std::cout << CW_STR("[13] Wide String Encryption Demo") << std::endl;

    const wchar_t* wide_msg = CW_WSTR(L"this is an encrypted wide string!");
    std::wcout << L"   encrypted wide string: " << wide_msg << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 14. COMPILE-TIME STRING HASHING
    // ==================================================================
    std::cout << CW_STR("[14] Compile-Time String Hashing Demo") << std::endl;

    // compile-time hash - computed at build time
    constexpr uint32_t kernel32_hash = CW_HASH("kernel32.dll");
    constexpr uint32_t ntdll_hash = CW_HASH("ntdll.dll");

    std::cout << CW_STR("   hash of 'kernel32.dll': 0x") << std::hex << kernel32_hash << std::dec << std::endl;
    std::cout << CW_STR("   hash of 'ntdll.dll': 0x") << std::hex << ntdll_hash << std::dec << std::endl;

    // runtime hash comparison
    auto test_str = CW_STR("kernel32.dll");
    uint32_t runtime_hash = CW_HASH_RT(test_str);
    std::cout << CW_STR("   runtime hash matches compile-time: ") << (runtime_hash == kernel32_hash ? CW_STR("yes") : CW_STR("no")) << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 15. IMPORT HIDING / DYNAMIC API RESOLUTION
    // ==================================================================
    std::cout << CW_STR("[15] Import Hiding Demo") << std::endl;
    std::cout << CW_STR("   resolving APIs without import table...") << std::endl;

    // get ntdll base address by hash (use case-insensitive hash for module names)
    void* ntdll_base = CW_GET_MODULE("ntdll.dll");
    std::cout << CW_STR("   ntdll.dll base: 0x") << std::hex << reinterpret_cast<uintptr_t>(ntdll_base) << std::dec << std::endl;

    // get kernel32 base
    void* k32_base = CW_GET_MODULE("kernel32.dll");
    std::cout << CW_STR("   kernel32.dll base: 0x") << std::hex << reinterpret_cast<uintptr_t>(k32_base) << std::dec << std::endl;

    // resolve function by hash
    if (ntdll_base) {
        void* nt_close = CW_GET_PROC(ntdll_base, "NtClose");
        std::cout << CW_STR("   NtClose address: 0x") << std::hex << reinterpret_cast<uintptr_t>(nt_close) << std::dec << std::endl;
    }

    std::cout << CW_STR("   (these functions are not in the import table!)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 16. DIRECT SYSCALL NUMBERS
    // ==================================================================
    std::cout << CW_STR("[16] Direct Syscall Demo") << std::endl;

    uint32_t syscall_NtClose = CW_SYSCALL_NUMBER(NtClose);
    uint32_t syscall_NtQueryInformationProcess = CW_SYSCALL_NUMBER(NtQueryInformationProcess);

    std::cout << CW_STR("   NtClose syscall number: 0x") << std::hex << syscall_NtClose << std::dec << std::endl;
    std::cout << CW_STR("   NtQueryInformationProcess syscall number: 0x") << std::hex << syscall_NtQueryInformationProcess << std::dec << std::endl;
    std::cout << CW_STR("   SYSCALL_ERROR sentinel: 0x") << std::hex << cloakwork::syscall::SYSCALL_ERROR << std::dec << std::endl;
    std::cout << CW_STR("   (syscall numbers are OS version dependent, SYSCALL_ERROR = UINT32_MAX on failure)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 17. ANTI-VM/SANDBOX DETECTION
    // ==================================================================
    std::cout << CW_STR("[17] Anti-VM/Sandbox Detection Demo") << std::endl;
    std::cout << CW_STR("   running VM/sandbox detection checks...") << std::endl;

    // use namespace functions for granular checks
    if (cloakwork::anti_debug::anti_vm::is_hypervisor_present()) {
        std::cout << CW_STR("   INFO: hypervisor detected") << std::endl;
    } else {
        std::cout << CW_STR("   hypervisor check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::anti_vm::detect_vm_vendor()) {
        std::cout << CW_STR("   INFO: VM vendor signature detected") << std::endl;
    } else {
        std::cout << CW_STR("   VM vendor check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::anti_vm::detect_low_resources()) {
        std::cout << CW_STR("   INFO: low resources detected (possible sandbox)") << std::endl;
    } else {
        std::cout << CW_STR("   resource check: clean") << std::endl;
    }

    if (cloakwork::anti_debug::anti_vm::detect_sandbox_dlls()) {
        std::cout << CW_STR("   INFO: sandbox DLLs detected") << std::endl;
    } else {
        std::cout << CW_STR("   sandbox DLL check: clean") << std::endl;
    }

    if (CW_CHECK_VM()) {
        std::cout << CW_STR("   COMPREHENSIVE: VM/sandbox detected (CW_ANTI_VM would crash)") << std::endl;
    } else {
        std::cout << CW_STR("   COMPREHENSIVE: all VM/sandbox checks passed") << std::endl;
    }

    std::cout << std::endl;

    // ==================================================================
    // 18. OBFUSCATED COMPARISONS
    // ==================================================================
    std::cout << CW_STR("[18] Obfuscated Comparisons Demo") << std::endl;

    int cmp_a = 42;
    int cmp_b = 42;
    int cmp_c = 100;

    std::cout << CW_STR("   CW_EQ(42, 42) = ") << (CW_EQ(cmp_a, cmp_b) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   CW_NE(42, 100) = ") << (CW_NE(cmp_a, cmp_c) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   CW_LT(42, 100) = ") << (CW_LT(cmp_a, cmp_c) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   CW_GT(100, 42) = ") << (CW_GT(cmp_c, cmp_a) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   CW_LE(42, 42) = ") << (CW_LE(cmp_a, cmp_b) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   CW_GE(100, 42) = ") << (CW_GE(cmp_c, cmp_a) ? "true" : "false") << CW_STR(" (expected: true)") << std::endl;
    std::cout << CW_STR("   (comparisons use MBA and XOR to hide the actual operation)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 19. ENCRYPTED CONSTANTS
    // ==================================================================
    std::cout << CW_STR("[19] Encrypted Constants Demo") << std::endl;

    // compile-time encrypted constant
    int encrypted_magic = CW_CONST(0xDEADBEEF);
    std::cout << CW_STR("   CW_CONST(0xDEADBEEF) = 0x") << std::hex << encrypted_magic << std::dec << std::endl;

    int encrypted_value = CW_CONST(12345);
    std::cout << CW_STR("   CW_CONST(12345) = ") << encrypted_value << std::endl;

    // runtime constant (different key each execution)
    cloakwork::rt_const<int> rt_val(9999);
    std::cout << CW_STR("   runtime_constant(9999) = ") << rt_val.get() << std::endl;
    std::cout << CW_STR("   (constants are XOR-encrypted and decrypted at runtime)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 20. JUNK CODE INSERTION
    // ==================================================================
    std::cout << CW_STR("[20] Junk Code Insertion Demo") << std::endl;

    std::cout << CW_STR("   inserting junk computation...") << std::endl;
    CW_JUNK();
    std::cout << CW_STR("   junk computation complete") << std::endl;

    std::cout << CW_STR("   inserting junk control flow...") << std::endl;
    CW_JUNK_FLOW();
    std::cout << CW_STR("   junk control flow complete") << std::endl;

    std::cout << CW_STR("   (junk code confuses decompilers and increases entropy)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 21. RETURN ADDRESS SPOOFING
    // ==================================================================
    std::cout << CW_STR("[21] Return Address Spoofing Demo") << std::endl;

    void* ret_gadget = CW_RET_GADGET();
    std::cout << CW_STR("   found ret gadget at: 0x") << std::hex << reinterpret_cast<uintptr_t>(ret_gadget) << std::dec << std::endl;
    std::cout << CW_STR("   (can be used to spoof return addresses in call stacks)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 22. INTEGRITY VERIFICATION
    // ==================================================================
    std::cout << CW_STR("[22] Integrity Verification Demo") << std::endl;

    // check if our own functions are hooked
    bool simple_add_hooked = CW_DETECT_HOOK(simple_add);
    std::cout << CW_STR("   simple_add hook check: ") << (simple_add_hooked ? CW_STR("HOOKED!") : "clean") << std::endl;

    // compute hash of function
    uint32_t func_hash = CW_COMPUTE_HASH(
        reinterpret_cast<const void*>(&simple_add), 32);
    std::cout << CW_STR("   simple_add code hash: 0x") << std::hex << func_hash << std::dec << std::endl;

    // verify multiple functions at once
    bool all_clean = CW_VERIFY_FUNCS(&simple_add, &simple_add_v2);
    std::cout << CW_STR("   all functions clean: ") << (all_clean ? "yes" : CW_STR("NO - hooks detected!")) << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 23. STACK STRING BUILDER
    // ==================================================================
    std::cout << CW_STR("[23] Stack String Builder Demo") << std::endl;

    // build a string char-by-char on the stack - never appears as a literal in the binary
    CW_STACK_STR(stack_hello, 'h','e','l','l','o',' ','f','r','o','m',' ','s','t','a','c','k','\0');
    std::cout << CW_STR("   stack-built string: ") << stack_hello << std::endl;
    std::cout << CW_STR("   (string never exists as a contiguous literal in the binary)") << std::endl;
    std::cout << CW_STR("   (each char is placed individually, then touched through a stack-time key)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 24. PE HEADER ERASURE
    // ==================================================================
    std::cout << CW_STR("[24] PE Header Erasure Demo") << std::endl;

    std::cout << CW_STR("   CW_ERASE_PE_HEADER() is available") << std::endl;
    std::cout << CW_STR("   (zeros DOS header, NT headers, and section table to prevent dumping)") << std::endl;
    std::cout << CW_STR("   NOTE: not called here - would break the running demo executable") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 25. ENHANCED ANTI-DEBUG (namespace functions)
    // ==================================================================
    std::cout << CW_STR("[25] Enhanced Anti-Debug Demo") << std::endl;

    // debug port check via NtQueryInformationProcess
    bool debug_port = cloakwork::anti_debug::enhanced::check_debug_port();
    std::cout << CW_STR("   debug port check: ") << (debug_port ? CW_STR("DEBUGGER DETECTED") : "clean") << std::endl;
    std::cout << CW_STR("   (queries ProcessDebugPort + ProcessDebugObjectHandle via NtQueryInformationProcess)") << std::endl;

    // hide thread from debugger - available but not called to keep demo debuggable
    std::cout << CW_STR("   CW_HIDE_THREAD() is available") << std::endl;
    std::cout << CW_STR("   (uses NtSetInformationThread with ThreadHideFromDebugger)") << std::endl;
    std::cout << CW_STR("   NOTE: not called here - would hide this thread from attached debuggers") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 26. INDIRECT SYSCALLS
    // ==================================================================
    std::cout << CW_STR("[26] Indirect Syscall Demo") << std::endl;

    // invoke NtClose via indirect syscall with an invalid handle to demonstrate the mechanism
    // NtClose(INVALID_HANDLE_VALUE) returns STATUS_INVALID_HANDLE (0xC0000008) which is expected
    NTSTATUS nt_result = CW_SYSCALL(NtClose, INVALID_HANDLE_VALUE);
    std::cout << CW_STR("   CW_SYSCALL(NtClose, INVALID_HANDLE_VALUE) = 0x") << std::hex << static_cast<uint32_t>(nt_result) << std::dec << std::endl;
    std::cout << CW_STR("   (expected: STATUS_INVALID_HANDLE 0xC0000008 or similar)") << std::endl;
    std::cout << CW_STR("   (syscall executed through ntdll gadget - return address points to ntdll)") << std::endl;

    std::cout << std::endl;

    // ==================================================================
    // 27. ENCRYPTED MESSAGE OUTPUT
    // ==================================================================
    std::cout << CW_STR("[27] Final Encrypted Output") << std::endl;

    // all these strings are encrypted and have unique runtime keys
    std::cout << "    " << CW_STR("this demo showcases:") << std::endl;
    std::cout << "    - " << CW_STR_LAYERED("multi-layer compile-time string encryption") << std::endl;
    std::cout << "    - " << CW_STR_LAYERED("wide string encryption (wchar_t)") << std::endl;
    std::cout << "    - " << CW_STR("compile-time string hashing (FNV-1a)") << std::endl;
    std::cout << "    - " << CW_STR("mixed boolean arithmetic (MBA) obfuscation") << std::endl;
    std::cout << "    - " << CW_STR("boolean obfuscation with opaque predicates") << std::endl;
    std::cout << "    - " << CW_STR("obfuscated comparison operators") << std::endl;
    std::cout << "    - " << CW_STR("encrypted compile-time constants") << std::endl;
    std::cout << "    - " << CW_STR("control flow obfuscation and flattening") << std::endl;
    std::cout << "    - " << CW_STR("CFG protection (encrypted state machine via CW_PROTECT)") << std::endl;
    std::cout << "    - " << CW_STR("junk code insertion") << std::endl;
    std::cout << "    - " << CW_STR("function pointer encryption") << std::endl;
    std::cout << "    - " << CW_STR("metamorphic function implementations") << std::endl;
    std::cout << "    - " << CW_STR("import hiding / dynamic API resolution") << std::endl;
    std::cout << "    - " << CW_STR("direct syscall number extraction") << std::endl;
    std::cout << "    - " << CW_STR("return address spoofing infrastructure") << std::endl;
    std::cout << "    - " << CW_STR("comprehensive anti-debug protection") << std::endl;
    std::cout << "    - " << CW_STR("anti-VM/sandbox detection") << std::endl;
    std::cout << "    - " << CW_STR("code integrity verification / hook detection") << std::endl;

    std::cout << "    - " << CW_STR("compile-time string encoding with scoped plaintext buffers") << std::endl;
    std::cout << "    - " << CW_STR("indirect syscall invocation") << std::endl;
    std::cout << "    - " << CW_STR("PE header erasure") << std::endl;
    std::cout << "    - " << CW_STR("stack string builder") << std::endl;
    std::cout << "    - " << CW_STR("enhanced anti-debug (NtQueryInformationProcess)") << std::endl;
    std::cout << "    - " << CW_STR("kernel mode driver support (WDM/KMDF)") << std::endl;

    std::cout << std::endl;
    std::cout << CW_STR("=== DEMO COMPLETE ===") << std::endl;
    std::cout << std::endl;

    // ==================================================================
    // INTERACTIVE EXIT
    // ==================================================================
    std::cout << CW_STR("press enter to exit (protected)...") << std::endl;
    std::cin.get();

    // obfuscated return value
    return CW_MBA(0);
}

// ==================================================================
// KERNEL MODE EXAMPLE (not compiled - for reference only)
// ==================================================================
//
// Cloakwork supports Windows kernel mode drivers. However, due to kernel
// constraints (no STL, no CRT atexit, no C++20 concepts), most obfuscation
// features are DISABLED by default in kernel mode.
//
// WHAT WORKS in kernel mode:
// - Compile-time random generation (CW_RANDOM_CT, CW_RAND_CT)
// - Runtime random generation (CW_RANDOM_RT, CW_RAND_RT)
// - Compile-time string hashing (CW_HASH, CW_HASH_CI, CW_HASH_WIDE)
// - Anti-debug (kernel debugger detection, hardware breakpoints)
//
// WHAT DOES NOT WORK (compiles to no-ops):
// - CW_STR, CW_STR_LAYERED, CW_WSTR (string encryption disabled)
// - CW_INT, CW_MBA (value obfuscation disabled)
// - CW_IF, CW_ELSE, CW_BRANCH (control flow disabled)
// - CW_TRUE, CW_FALSE, CW_BOOL (opaque predicates disabled)
// - CW_ADD, CW_SUB, CW_EQ, etc. (MBA operations disabled)
// - CW_CALL, CW_SPOOF_CALL (function obfuscation disabled)
// - CW_SCATTER, CW_POLY (data hiding disabled)
// - CW_ANTI_VM, CW_CHECK_VM (anti-VM disabled)
// - CW_JUNK, CW_JUNK_FLOW (junk code disabled)
// - CW_IMPORT (import hiding disabled)
// - CW_DETECT_HOOK (integrity checks disabled)
//
// ```cpp
// #include <ntddk.h>
// #include "cloakwork.h"  // auto-detects kernel mode via _NTDDK_
//
// NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
//     UNREFERENCED_PARAMETER(RegistryPath);
//
//     // ===== COMPILE-TIME STRING HASHING (WORKS) =====
//     // these are consteval so they work in any mode
//     constexpr uint32_t nt_close_hash = CW_HASH("NtClose");
//     constexpr uint32_t ntoskrnl_hash = CW_HASH_CI("ntoskrnl.exe");
//     DbgPrint("NtClose hash: 0x%X\n", nt_close_hash);
//     DbgPrint("ntoskrnl hash: 0x%X\n", ntoskrnl_hash);
//
//     // runtime hash comparison
//     const char* func_name = "NtClose";
//     uint32_t runtime_hash = cloakwork::hash::fnv1a_runtime(func_name);
//     if (runtime_hash == nt_close_hash) {
//         DbgPrint("Hash match!\n");
//     }
//
//     // ===== COMPILE-TIME RANDOM (WORKS) =====
//     constexpr uint32_t build_key = CW_RANDOM_CT();
//     constexpr int random_index = CW_RAND_CT(0, 255);
//     DbgPrint("Build key: 0x%X, Random index: %d\n", build_key, random_index);
//
//     // ===== RUNTIME RANDOM (WORKS) =====
//     // uses kernel entropy: rdtsc, KeQueryPerformanceCounter, KASLR, etc.
//     uint64_t runtime_key = CW_RANDOM_RT();
//     uint64_t random_value = CW_RAND_RT(1000, 9999);
//     DbgPrint("Runtime key: 0x%llX, Random value: %llu\n", runtime_key, random_value);
//
//     // ===== ANTI-DEBUG (WORKS) =====
//     // kernel debugger detection
//     if (cloakwork::anti_debug::is_debugger_present()) {
//         DbgPrint("Kernel debugger detected!\n");
//         // KdDebuggerEnabled, KdDebuggerNotPresent, or PsIsProcessBeingDebugged
//     }
//
//     // hardware breakpoint detection via debug registers (DR0-DR3)
//     if (cloakwork::anti_debug::has_hardware_breakpoints()) {
//         DbgPrint("Hardware breakpoints detected!\n");
//     }
//
//     // timing check for single-stepping
//     bool suspicious = cloakwork::anti_debug::timing_check([]() {
//         volatile int x = 0;
//         for (int i = 0; i < 100; i++) x += i;
//     }, 50000);
//     if (suspicious) {
//         DbgPrint("Suspicious timing detected!\n");
//     }
//
//     // comprehensive check (combines all)
//     if (cloakwork::anti_debug::comprehensive_check()) {
//         DbgPrint("Analysis detected - crashing!\n");
//         KeBugCheckEx(0xDEAD, 0, 0, 0, 0);
//     }
//
//     // ===== THINGS THAT DON'T WORK (NO-OPS) =====
//     // these compile but provide NO protection in kernel mode:
//     const char* msg = CW_STR("this is NOT encrypted");  // just returns "this is NOT encrypted"
//     // CW_INT, CW_IF, CW_TRUE, etc. are all no-ops
//
//     DriverObject->DriverUnload = [](PDRIVER_OBJECT) {
//         DbgPrint("Driver unloading\n");
//     };
//
//     return STATUS_SUCCESS;
// }
// ```
//
// Kernel mode internal replacements:
// - std::mutex      -> KSPIN_LOCK (kernel_spinlock class)
// - std::atomic<T>  -> Interlocked* (kernel_atomic<T> class)
// - new/HeapAlloc   -> ExAllocatePool2/ExFreePoolWithTag
// - type traits     -> custom std::is_integral, std::enable_if, etc.
// - std::array      -> custom implementation
// - std::rotl/rotr  -> custom implementation
//
// Kernel entropy sources for CW_RANDOM_RT:
// - __rdtsc()                  - CPU cycle counter
// - PsGetCurrentProcess/Thread - KASLR randomized addresses
// - KeQueryPerformanceCounter  - High-precision timer
// - KeQuerySystemTime          - System time
// - KeQueryInterruptTime       - Interrupt time
// - Pool allocation addresses  - KASLR randomized
// - Stack addresses            - KASLR randomized
//
