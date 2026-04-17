// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Zero-Knowledge TLS Pin Validator — C Level
//
// Security properties:
// 1. Expected TLS pins NEVER exist in plaintext RAM
// 2. Server cert hash is blinded before comparison: H(salt || cert_hash)
// 3. Comparison against pre-blinded Genesis/Dynamic pins only
// 4. Constant-time comparison prevents timing side-channel attacks
// 5. All intermediate buffers volatile-wiped after use

#include "AranPinValidator.h"
#include "AranGenesis.h"
#include <string.h>
#include <CommonCrypto/CommonDigest.h>

// ============================================================================
// MARK: - Constant-Time Comparison
// ============================================================================

int aran_secure_compare(const uint8_t* a, const uint8_t* b, uint32_t len) {
    volatile uint8_t result = 0;
    for (uint32_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return (int)result;
}

// ============================================================================
// MARK: - Zero-Knowledge Blinded Pin Verification
// ============================================================================

int aran_verify_cert_blinded(const uint8_t* server_cert_hash, uint32_t hash_len) {
    if (!server_cert_hash || hash_len != CC_SHA256_DIGEST_LENGTH) {
        return 0;
    }

    // Step 1: Load the Genesis state to get blinding salt and blinded pins.
    //         The actual expected pin values are NEVER decoded — only blinded forms.
    AranGenesisState genesis = aran_load_genesis_state();

    // Step 2: Blind the incoming server certificate hash with the same salt.
    //         blinded_server = SHA256(blinding_salt || server_cert_hash)
    //         This means: even the server's cert hash doesn't persist in usable form.
    volatile uint8_t blinded_server[CC_SHA256_DIGEST_LENGTH];
    {
        CC_SHA256_CTX ctx;
        CC_SHA256_Init(&ctx);
        CC_SHA256_Update(&ctx, genesis.blinding_salt, ARAN_GENESIS_SALT_LEN);
        CC_SHA256_Update(&ctx, server_cert_hash, hash_len);
        CC_SHA256_Final((unsigned char*)blinded_server, &ctx);
    }

    // Step 3: Constant-time compare against each blinded pin.
    //         Neither the expected pin NOR the blinding salt remains useful
    //         in a memory dump — only H(salt||expected) and H(salt||actual) exist.
    int pin0_match = aran_secure_compare(
        (const uint8_t*)blinded_server,
        genesis.tls_pins_blinded[0],
        CC_SHA256_DIGEST_LENGTH
    );

    int pin1_match = aran_secure_compare(
        (const uint8_t*)blinded_server,
        genesis.tls_pins_blinded[1],
        CC_SHA256_DIGEST_LENGTH
    );

    // Step 4: Wipe ALL intermediates from RAM.
    //         Genesis state, blinded server hash — everything.
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        blinded_server[i] = 0;
    }
    aran_wipe_genesis_state(&genesis);

    // pin0_match == 0 means EQUAL (constant-time compare returns 0 on match)
    return (pin0_match == 0 || pin1_match == 0) ? 1 : 0;
}
