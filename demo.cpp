#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace cloakwork { enum class detection_reason; }
void on_detection(cloakwork::detection_reason reason);

#define CW_ANTI_DEBUG_RESPONSE 3
#define CW_DETECTION_CALLBACK(reason) on_detection(reason)
#include "cloakwork.h"

void on_detection(cloakwork::detection_reason reason) {
    const char* name = "unknown";
    switch (reason) {
    case cloakwork::detection_reason::debugger: name = "debugger"; break;
    case cloakwork::detection_reason::virtual_machine: name = "VM/sandbox"; break;
    case cloakwork::detection_reason::integrity_failure: name = "code changed"; break;
    }
    std::cout << "  callback: " << name << ", continuing\n";
}

namespace {
    void strings() {
        auto local = CW_STR_STACK("local buffer");
        CW_STACK_STR(chars, 'h', 'e', 'l', 'l', 'o', '\0');

        std::cout << "\nstrings\n"
                  << "  CW_STR: " << CW_STR("config.toml") << '\n'
                  << "  CW_STR_LAYERED: " << CW_STR_LAYERED("session token") << '\n'
                  << "  CW_STR_STACK: " << local.get() << '\n'
                  << "  CW_STACK_STR: " << chars << '\n';
        std::wcout << L"  CW_WSTR: " << CW_WSTR(L"wide text") << L'\n';

        constexpr auto hash = CW_HASH_CI("NTDLL.DLL");
        std::cout << "  compile-time/runtime hash match: "
                  << (hash == CW_HASH_RT_CI(CW_STR("ntdll.dll"))) << '\n';
    }

    void values() {
        auto number = CW_INT(42);
        number.set(CW_ADD(number.get(), 8));
        auto encoded = CW_MBA(100);
        auto balance = CW_POLY(1200);
        balance.rekey();
        cloakwork::authenticated_value<uint64_t> verified_balance{1200};
        verified_balance.set(1300);

        struct account { uint32_t id, flags; };
        account source{7, 3};
        auto scattered = CW_SCATTER(source);
        const auto restored = scattered.get();
        cloakwork::obf_bool allowed(CW_LT(number.get(), encoded.get()));

        std::cout << "\nvalues\n"
                  << "  CW_INT after adding 8: " << number.get() << '\n'
                  << "  CW_MBA minus 50: " << CW_SUB(encoded.get(), 50) << '\n'
                  << "  CW_POLY after rekey: " << balance.get() << '\n'
                  << "  authenticated value: " << verified_balance.get() << '\n'
                  << "  CW_SCATTER: id=" << restored.id << ", flags=" << restored.flags << '\n'
                  << "  stored comparison: " << allowed.get() << '\n'
                  << "  CW_CONST: 0x" << std::hex << CW_CONST(0xC10Au) << std::dec << '\n';
    }

    CW_NOINLINE int add(int a, int b) {
        return a + b;
    }

    void calls_and_flow() {
        auto wrapped = CW_CALL(add);
        cloakwork::meta_func<int(int, int)> metamorphic(add);
        constexpr auto policy = cloakwork::call_protection::encoded | cloakwork::call_protection::integrity;
        cloakwork::protected_function<int(int, int), policy> checked(add, 1);

        std::cout << "\ncalls and control flow\n"
                  << "  CW_CALL: " << wrapped(19, 23) << '\n'
                  << "  meta_func: " << metamorphic(19, 23) << '\n'
                  << "  composed call, entry-byte check: " << checked(19, 23) << '\n'
                  << "  CW_FLATTEN: " << CW_FLATTEN(add, 19, 23) << '\n';

        //
        // CW_PROTECT dispatches the body; the loop is still native C++.
        //
        const int sum = CW_PROTECT(int, {
            int total = 0;
            for (int i = 1; i <= 5; ++i) total = CW_ADD(total, i);
            CW_JUNK();
            return total;
        });
        std::cout << "  CW_PROTECT sum 1..5: " << sum << '\n';

        CW_IF(CW_EQ(sum, 15)) {
            std::cout << "  CW_IF: sum matches\n";
        } CW_ELSE {
            throw std::runtime_error("unexpected sum from CW_PROTECT");
        }
    }

    void integer_vm() {
        using cloakwork::vm::instruction;
        using op = cloakwork::vm::opcode;

        //
        // Sum 1..n. r0 holds n, r1 starts at zero, r2 holds the decrement.
        // Fields are opcode, destination, a, b, immediate; jumps use instruction indices.
        //
        static constexpr auto sum = cloakwork::vm::make_program<CW_RANDOM_CT()>(std::array{
            instruction{op::argument, 0},
            instruction{op::constant, 2, 0, 0, 1},
            instruction{op::jump_zero, 0, 0, 0, 6},
            instruction{op::add, 1, 1, 0},
            instruction{op::sub, 0, 0, 2},
            instruction{op::jump, 0, 0, 0, 2},
            instruction{op::ret, 0, 1}
        });

        const auto result = sum.run(std::array{uint64_t{5}}, 64);
        if (!result) {
            throw std::runtime_error("integer VM error " + std::to_string(static_cast<int>(result.status)));
        }
        std::cout << "\ninteger VM\n"
                  << "  sum 1..5: " << result.value << ", steps: " << result.steps << '\n';
    }

    void windows_apis() {
        const auto get_pid = CW_IMPORT("kernel32.dll", GetCurrentProcessId);
        if (!get_pid) throw std::runtime_error("could not resolve GetCurrentProcessId");

        std::cout << "\nWindows APIs\n"
                  << "  imported GetCurrentProcessId: " << get_pid() << '\n'
                  << "  ntdll ret gadget: " << CW_RET_GADGET() << '\n'
                  << "  NtClose syscall number: ";
        const auto number = CW_SYSCALL_NUMBER(NtClose);
        if (number == cloakwork::syscall::SYSCALL_ERROR) {
            std::cout << "unavailable\n";
        } else {
            std::cout << "0x" << std::hex << number << std::dec << '\n';
        }
    }

    void detection_and_integrity() {
        std::cout << "\ndetection and integrity\n"
                  << "  debugger check: " << CW_CHECK_DEBUG() << '\n'
                  << "  VM/sandbox check: " << CW_CHECK_VM() << '\n';
        CW_ANTI_DEBUG();
        CW_ANTI_VM();

        std::array<uint8_t, 4> data{1, 2, 3, 4};
        const auto before = CW_COMPUTE_HASH(data.data(), data.size());
        data[0] = 5;
        const auto after = CW_COMPUTE_HASH(data.data(), data.size());
        std::cout << "  data hash before/after edit: 0x" << std::hex << before
                  << " / 0x" << after << std::dec << '\n'
                  << "  add entry matches a hook pattern: " << CW_DETECT_HOOK(add) << '\n';
    }
}

int main() {
    try {
        std::cout << std::boolalpha << "Cloakwork\n";
        strings();
        values();
        calls_and_flow();
        integer_vm();
        windows_apis();
        detection_and_integrity();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "demo: " << error.what() << '\n';
        return 1;
    }
}
