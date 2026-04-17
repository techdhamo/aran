// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Genesis Anchor — White-Box JNI Core
//
// XOR-chain + bitwise rotation obfuscation prevents:
// 1. Static binary string scanning (no plaintext keys in .rodata)
// 2. Simple XOR key recovery (chaining makes each byte depend on previous)
// 3. Fridump / memory dumping (volatile wipe after KeyStore seal)
// 4. Frida hook interception (crypto stays entirely in native)

#ifndef ARAN_GENESIS_H
#define ARAN_GENESIS_H

#include <cstdint>
#include <cstddef>
#include <cstring>

// ============================================================================
// Constants
// ============================================================================

#define ARAN_GENESIS_AES_KEY_LEN     32
#define ARAN_GENESIS_HMAC_SECRET_LEN 32
#define ARAN_GENESIS_PIN_LEN         32
#define ARAN_GENESIS_SALT_LEN        16
#define ARAN_GENESIS_ENDPOINT_LEN    256
#define ARAN_GENESIS_PIN_COUNT       2

// ============================================================================
// Genesis State Structure
// ============================================================================

struct AranGenesisState {
    uint8_t  aes_key[ARAN_GENESIS_AES_KEY_LEN];
    uint8_t  hmac_secret[ARAN_GENESIS_HMAC_SECRET_LEN];
    uint8_t  tls_pins_blinded[ARAN_GENESIS_PIN_COUNT][ARAN_GENESIS_PIN_LEN];
    uint8_t  blinding_salt[ARAN_GENESIS_SALT_LEN];
    uint8_t  default_reaction_policy;   // 3 = KILL_APP
    uint32_t config_version;
    uint32_t sync_interval_seconds;
    char     sync_endpoint[ARAN_GENESIS_ENDPOINT_LEN];
    char     license_endpoint[ARAN_GENESIS_ENDPOINT_LEN];
};

// ============================================================================
// Embedded SHA-256 (no OpenSSL dependency — stays entirely in native)
// ============================================================================

struct AranSHA256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
};

void aran_sha256_init(AranSHA256Ctx* ctx);
void aran_sha256_update(AranSHA256Ctx* ctx, const uint8_t* data, size_t len);
void aran_sha256_final(AranSHA256Ctx* ctx, uint8_t hash[32]);
void aran_sha256(const uint8_t* data, size_t len, uint8_t hash[32]);

// ============================================================================
// XOR-Chain Obfuscation
// ============================================================================

void aran_xor_chain_encode(const uint8_t* plain, uint8_t* encoded, size_t len, uint8_t field_key);
void aran_xor_chain_decode(const uint8_t* encoded, volatile uint8_t* decoded, size_t len, uint8_t field_key);

// ============================================================================
// Security Utilities
// ============================================================================

void aran_secure_wipe(volatile void* ptr, size_t len);
int  aran_secure_compare(const uint8_t* a, const uint8_t* b, size_t len);
void aran_blind_pin_hash(const uint8_t* pin_sha256, const uint8_t* salt, size_t salt_len, uint8_t* blinded_out);

// ============================================================================
// Genesis State API
// ============================================================================

AranGenesisState aran_load_genesis_state();
void aran_wipe_genesis_state(AranGenesisState* state);

void aran_update_dynamic_pins(const uint8_t* pin0, uint32_t pin0_len, const uint8_t* pin1, uint32_t pin1_len);
int  aran_has_dynamic_pins();

// ============================================================================
// Zero-Knowledge Blinded Pin Verification
// ============================================================================

int aran_verify_cert_blinded(const uint8_t* server_cert_hash, uint32_t hash_len);

// ============================================================================
// Base64 Encoding (for JNI JSON return)
// ============================================================================

void aran_base64_encode(const uint8_t* data, size_t len, char* out, size_t out_max);

#endif // ARAN_GENESIS_H
