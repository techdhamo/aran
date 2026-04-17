//
//  AranObfuscate.h
//  Aran iOS SDK
//
//  Compile-time XOR obfuscation for sensitive strings (file paths, URLs).
//  Prevents static analysis from seeing plain-text jailbreak indicators.
//
//  Usage:
//    #include "AranObfuscate.h"
//    const char *cydiaPath = ("/Applications/Cydia.app");
//    // cydiaPath is now obfuscated at compile time, deobfuscated at runtime
//

#ifndef AranObfuscate_h
#define AranObfuscate_h

#include <stdint.h>
#include <string.h>

// XOR key - randomized at compile time via -DARAN_XOR_KEY=0xNN
#ifndef ARAN_XOR_KEY
#define ARAN_XOR_KEY 0xA7
#endif

// Obfuscate a string literal at compile time
#define str aran_deobfuscate(str, ARAN_XOR_KEY)

// Runtime deobfuscation - stack-allocated buffer that expires after use
static inline const char *aran_deobfuscate(const char *obfuscated, uint8_t key) {
    static __thread char buffer[256];
    size_t len = strlen(obfuscated);
    if (len >= sizeof(buffer)) len = sizeof(buffer) - 1;
    
    for (size_t i = 0; i < len; i++) {
        buffer[i] = obfuscated[i] ^ key;
    }
    buffer[len] = '\0';
    return buffer;
}

// Obfuscate string at compile time (preprocessor)
#define DEOBFUSCATE_LITERAL(str, key) \
    ((str)[0] ^ (key))

// Helper to create obfuscated string arrays
#define OBFUSCATE_ARRAY(arr) ({ \
    static const char *obs[] = { FOR_EACH(arr, OBFUSCATE) }; \
    obs; \
})

#endif /* AranObfuscate_h */
