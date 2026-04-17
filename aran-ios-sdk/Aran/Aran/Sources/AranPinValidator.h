// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

#ifndef AranPinValidator_h
#define AranPinValidator_h

#include <stdint.h>

// ============================================================================
// Zero-Knowledge TLS Pin Validator — C Level
//
// Validates server certificate hashes WITHOUT ever decrypting the expected
// TLS pin into plaintext RAM. The algorithm:
//
// 1. Server cert hash arrives from Swift (SHA-256 of DER certificate)
// 2. Apply cryptographic blinding: H(blinding_salt || server_cert_hash)
// 3. Compare blinded result against stored blinded Genesis/Dynamic pins
// 4. Comparison uses constant-time memcmp to prevent timing side-channels
// 5. The expected pin NEVER exists in cleartext — only blinded form
//
// This prevents:
// - RAM dump extraction of expected pins
// - Frida/LLDB memory scanning for pin values
// - Timing attacks on the comparison
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/// Verify a server certificate hash using zero-knowledge blinded comparison.
/// @param server_cert_hash SHA-256 hash of the server's DER-encoded certificate (32 bytes)
/// @param hash_len Length of the hash (must be 32)
/// @return 1 if the certificate matches a known pin (Genesis or Dynamic), 0 if invalid
int aran_verify_cert_blinded(const uint8_t* server_cert_hash, uint32_t hash_len);

/// Constant-time memory comparison (prevents timing side-channel attacks).
/// @return 0 if equal, non-zero if different
int aran_secure_compare(const uint8_t* a, const uint8_t* b, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* AranPinValidator_h */
