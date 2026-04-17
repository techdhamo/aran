#pragma once
#include <cstddef>
#include <cstring>

// ============================================================
// Aran Compile-Time String Obfuscation
// ============================================================
// ARAN_OBFUSCATE_KEY is injected by CMakeLists.txt at build
// time using a randomly generated value (1-255). This ensures
// that string signatures change with every SDK release, making
// static analysis (strings/IDA/Ghidra) ineffective.
//
// Usage:
//   const char* s = ("/proc/self/maps");
//   // `s` is a stack pointer; string is plaintext only while
//   // the enclosing scope is live.
//
// Design:
//   - constexpr constructor: XOR happens at *compile* time
//     so no plaintext ever appears in .rodata
//   - Per-character rolling key: byte[i] ^= KEY ^ (i & 0xFF)
//     to break identical-char runs (e.g. "aaaa" won't produce
//     identical ciphertext bytes)
//   - decrypt() writes to a mutable stack buffer; caller
//     receives a raw pointer that is valid for the object's
//     lifetime. Use () macro which creates a temp
//     with statement-scope lifetime (sufficient for a single
//     call site).
// ============================================================

#ifndef ARAN_OBFUSCATE_KEY
#define ARAN_OBFUSCATE_KEY 0x7B
#endif

template <size_t N>
class AranObfuscatedString {
public:
    static constexpr unsigned char KEY = static_cast<unsigned char>(ARAN_OBFUSCATE_KEY);

    constexpr explicit AranObfuscatedString(const char (&str)[N]) : m_enc{} {
        for (size_t i = 0; i < N; ++i) {
            m_enc[i] = static_cast<char>(
                static_cast<unsigned char>(str[i]) ^ KEY ^ static_cast<unsigned char>(i & 0xFF)
            );
        }
    }

    const char* decrypt() const {
        for (size_t i = 0; i < N; ++i) {
            m_plain[i] = static_cast<char>(
                static_cast<unsigned char>(m_enc[i]) ^ KEY ^ static_cast<unsigned char>(i & 0xFF)
            );
        }
        return m_plain;
    }

private:
    char m_enc[N];
    mutable char m_plain[N]{};
};

#define str (AranObfuscatedString<sizeof(str)>(str).decrypt())
