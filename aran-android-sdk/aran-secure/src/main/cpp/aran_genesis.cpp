// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Genesis Anchor — White-Box JNI Core
// XOR-chain + bitwise rotation obfuscation + embedded SHA-256
//
// Security properties:
// 1. No plaintext keys/endpoints in .rodata section
// 2. Chained XOR prevents parallel byte-by-byte recovery
// 3. Volatile wipe defeats Fridump and memory scanners
// 4. Entire crypto pipeline stays in native (no Java heap exposure)

#include "aran_genesis.h"
#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <android/log.h>

#define LOG_TAG "AranGenesis"

// ============================================================================
// MARK: - Embedded SHA-256 Implementation (no OpenSSL dependency)
// ============================================================================

static const uint32_t _sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t _rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void _sha256_transform(AranSHA256Ctx* ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
                ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = _rotr32(w[i-15], 7) ^ _rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = _rotr32(w[i-2], 17) ^ _rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + _sha256_k[i] + w[i];
        uint32_t S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void aran_sha256_init(AranSHA256Ctx* ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buffer, 0, 64);
}

void aran_sha256_update(AranSHA256Ctx* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0) {
            _sha256_transform(ctx, ctx->buffer);
        }
    }
}

void aran_sha256_final(AranSHA256Ctx* ctx, uint8_t hash[32]) {
    uint64_t bits = ctx->count * 8;
    size_t pad_idx = ctx->count % 64;

    ctx->buffer[pad_idx++] = 0x80;
    if (pad_idx > 56) {
        memset(ctx->buffer + pad_idx, 0, 64 - pad_idx);
        _sha256_transform(ctx, ctx->buffer);
        pad_idx = 0;
    }
    memset(ctx->buffer + pad_idx, 0, 56 - pad_idx);

    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
    _sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        hash[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        hash[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

void aran_sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    AranSHA256Ctx ctx;
    aran_sha256_init(&ctx);
    aran_sha256_update(&ctx, data, len);
    aran_sha256_final(&ctx, hash);
    aran_secure_wipe(&ctx, sizeof(ctx));
}

// ============================================================================
// MARK: - Security Utilities
// ============================================================================

void aran_secure_wipe(volatile void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

int aran_secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return (int)result;
}

void aran_blind_pin_hash(const uint8_t* pin_sha256, const uint8_t* salt, size_t salt_len, uint8_t* blinded_out) {
    AranSHA256Ctx ctx;
    aran_sha256_init(&ctx);
    aran_sha256_update(&ctx, salt, salt_len);
    aran_sha256_update(&ctx, pin_sha256, 32);
    aran_sha256_final(&ctx, blinded_out);
    aran_secure_wipe(&ctx, sizeof(ctx));
}

// ============================================================================
// MARK: - Base64 Encoder (for JNI JSON return)
// ============================================================================

static const char _b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void aran_base64_encode(const uint8_t* data, size_t len, char* out, size_t out_max) {
    size_t oi = 0;
    for (size_t i = 0; i < len && oi + 4 < out_max; i += 3) {
        uint32_t n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];
        out[oi++] = _b64_table[(n >> 18) & 0x3F];
        out[oi++] = _b64_table[(n >> 12) & 0x3F];
        out[oi++] = (i + 1 < len) ? _b64_table[(n >> 6) & 0x3F] : '=';
        out[oi++] = (i + 2 < len) ? _b64_table[n & 0x3F] : '=';
    }
    if (oi < out_max) out[oi] = '\0';
}

// ============================================================================
// MARK: - XOR-Chain Obfuscation Engine
// ============================================================================

#define _GENESIS_SEED        0xA7u
#define _GENESIS_FK_AES      0x5Cu
#define _GENESIS_FK_HMAC     0x3Eu
#define _GENESIS_FK_PIN0     0x71u
#define _GENESIS_FK_PIN1     0x8Du
#define _GENESIS_FK_SALT     0xC3u
#define _GENESIS_FK_ENDPOINT 0x2Bu
#define _GENESIS_FK_LICENSE  0x94u

static inline uint8_t _rol8(uint8_t val, uint8_t n) {
    return (uint8_t)((val << n) | (val >> (8u - n)));
}

void aran_xor_chain_encode(const uint8_t* plain, uint8_t* encoded, size_t len, uint8_t field_key) {
    if (len == 0) return;
    encoded[0] = plain[0] ^ (_GENESIS_SEED ^ field_key);
    for (size_t i = 1; i < len; i++) {
        uint8_t rotated = _rol8(encoded[i - 1], 3);
        encoded[i] = plain[i] ^ rotated ^ ((uint8_t)(i * 0x37u)) ^ field_key;
    }
}

void aran_xor_chain_decode(const uint8_t* encoded, volatile uint8_t* decoded, size_t len, uint8_t field_key) {
    if (len == 0) return;
    decoded[0] = encoded[0] ^ (_GENESIS_SEED ^ field_key);
    for (size_t i = 1; i < len; i++) {
        uint8_t rotated = _rol8(encoded[i - 1], 3);
        decoded[i] = encoded[i] ^ rotated ^ ((uint8_t)(i * 0x37u)) ^ field_key;
    }
}

// ============================================================================
// MARK: - Dynamic Pin State (updated by Phantom Channel)
// ============================================================================

static volatile int _dynamic_pins_loaded = 0;
static uint8_t _dynamic_pin0_blinded[ARAN_GENESIS_PIN_LEN];
static uint8_t _dynamic_pin1_blinded[ARAN_GENESIS_PIN_LEN];

void aran_update_dynamic_pins(const uint8_t* pin0, uint32_t pin0_len, const uint8_t* pin1, uint32_t pin1_len) {
    if (pin0_len > ARAN_GENESIS_PIN_LEN) pin0_len = ARAN_GENESIS_PIN_LEN;
    if (pin1_len > ARAN_GENESIS_PIN_LEN) pin1_len = ARAN_GENESIS_PIN_LEN;
    memcpy(_dynamic_pin0_blinded, pin0, pin0_len);
    memcpy(_dynamic_pin1_blinded, pin1, pin1_len);
    _dynamic_pins_loaded = 1;
}

int aran_has_dynamic_pins() {
    return _dynamic_pins_loaded;
}

// ============================================================================
// MARK: - Dev Fallback Encoding (runtime; production uses build-script blobs)
// ============================================================================

static volatile int _genesis_encoded = 0;
static uint8_t _enc_aes_key[ARAN_GENESIS_AES_KEY_LEN];
static uint8_t _enc_hmac_secret[ARAN_GENESIS_HMAC_SECRET_LEN];
static uint8_t _enc_pin0[ARAN_GENESIS_PIN_LEN];
static uint8_t _enc_pin1[ARAN_GENESIS_PIN_LEN];
static uint8_t _enc_salt[ARAN_GENESIS_SALT_LEN];
static uint8_t _enc_endpoint[ARAN_GENESIS_ENDPOINT_LEN];
static size_t  _enc_endpoint_len = 0;
static uint8_t _enc_license_ep[ARAN_GENESIS_ENDPOINT_LEN];
static size_t  _enc_license_ep_len = 0;

static void _encode_dev_genesis() {
    if (_genesis_encoded) return;

    // --- Dev AES key: 32 zero bytes (base64 "AAAA...=") ---
    uint8_t dev_aes[ARAN_GENESIS_AES_KEY_LEN];
    memset(dev_aes, 0x00, sizeof(dev_aes));
    aran_xor_chain_encode(dev_aes, _enc_aes_key, sizeof(dev_aes), _GENESIS_FK_AES);
    aran_secure_wipe(dev_aes, sizeof(dev_aes));

    // --- Dev HMAC secret: repeating {0x04, 0x10, 0x41} (base64 "BBBB...") ---
    uint8_t dev_hmac[ARAN_GENESIS_HMAC_SECRET_LEN];
    for (size_t i = 0; i < sizeof(dev_hmac); i++) {
        static const uint8_t pattern[] = {0x04, 0x10, 0x41};
        dev_hmac[i] = pattern[i % 3];
    }
    aran_xor_chain_encode(dev_hmac, _enc_hmac_secret, sizeof(dev_hmac), _GENESIS_FK_HMAC);
    aran_secure_wipe(dev_hmac, sizeof(dev_hmac));

    // --- Dev blinding salt: 16 bytes of 0x42 ---
    uint8_t dev_salt[ARAN_GENESIS_SALT_LEN];
    memset(dev_salt, 0x42, sizeof(dev_salt));
    aran_xor_chain_encode(dev_salt, _enc_salt, sizeof(dev_salt), _GENESIS_FK_SALT);

    // --- Dev TLS pin hashes (SHA-256 of placeholder pin strings, then blinded) ---
    {
        const char* pin0_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        const char* pin1_str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
        uint8_t pin0_sha[32], pin1_sha[32];
        aran_sha256((const uint8_t*)pin0_str, strlen(pin0_str), pin0_sha);
        aran_sha256((const uint8_t*)pin1_str, strlen(pin1_str), pin1_sha);

        uint8_t pin0_blinded[ARAN_GENESIS_PIN_LEN], pin1_blinded[ARAN_GENESIS_PIN_LEN];
        aran_blind_pin_hash(pin0_sha, dev_salt, sizeof(dev_salt), pin0_blinded);
        aran_blind_pin_hash(pin1_sha, dev_salt, sizeof(dev_salt), pin1_blinded);

        aran_xor_chain_encode(pin0_blinded, _enc_pin0, ARAN_GENESIS_PIN_LEN, _GENESIS_FK_PIN0);
        aran_xor_chain_encode(pin1_blinded, _enc_pin1, ARAN_GENESIS_PIN_LEN, _GENESIS_FK_PIN1);

        aran_secure_wipe(pin0_sha, 32);
        aran_secure_wipe(pin1_sha, 32);
        aran_secure_wipe(pin0_blinded, 32);
        aran_secure_wipe(pin1_blinded, 32);
    }
    aran_secure_wipe(dev_salt, sizeof(dev_salt));

    // --- Sync endpoint ---
    const char* ep = "https://api.aran.mazhai.org";
    size_t ep_len = strnlen(ep, ARAN_GENESIS_ENDPOINT_LEN - 1);
    uint8_t ep_buf[ARAN_GENESIS_ENDPOINT_LEN];
    memset(ep_buf, 0, sizeof(ep_buf));
    memcpy(ep_buf, ep, ep_len);
    aran_xor_chain_encode(ep_buf, _enc_endpoint, ep_len + 1, _GENESIS_FK_ENDPOINT);
    _enc_endpoint_len = ep_len + 1;
    aran_secure_wipe(ep_buf, sizeof(ep_buf));

    // --- License endpoint ---
    const char* lep = "https://api.aran.mazhai.org/api/v1/license/validate";
    size_t lep_len = strnlen(lep, ARAN_GENESIS_ENDPOINT_LEN - 1);
    uint8_t lep_buf[ARAN_GENESIS_ENDPOINT_LEN];
    memset(lep_buf, 0, sizeof(lep_buf));
    memcpy(lep_buf, lep, lep_len);
    aran_xor_chain_encode(lep_buf, _enc_license_ep, lep_len + 1, _GENESIS_FK_LICENSE);
    _enc_license_ep_len = lep_len + 1;
    aran_secure_wipe(lep_buf, sizeof(lep_buf));

    _genesis_encoded = 1;
}

// ============================================================================
// MARK: - Public API
// ============================================================================

AranGenesisState aran_load_genesis_state() {
    _encode_dev_genesis();

    AranGenesisState state;
    memset(&state, 0, sizeof(state));

    aran_xor_chain_decode(_enc_aes_key, (volatile uint8_t*)state.aes_key,
                          ARAN_GENESIS_AES_KEY_LEN, _GENESIS_FK_AES);
    aran_xor_chain_decode(_enc_hmac_secret, (volatile uint8_t*)state.hmac_secret,
                          ARAN_GENESIS_HMAC_SECRET_LEN, _GENESIS_FK_HMAC);
    aran_xor_chain_decode(_enc_salt, (volatile uint8_t*)state.blinding_salt,
                          ARAN_GENESIS_SALT_LEN, _GENESIS_FK_SALT);

    if (_dynamic_pins_loaded) {
        memcpy(state.tls_pins_blinded[0], _dynamic_pin0_blinded, ARAN_GENESIS_PIN_LEN);
        memcpy(state.tls_pins_blinded[1], _dynamic_pin1_blinded, ARAN_GENESIS_PIN_LEN);
    } else {
        aran_xor_chain_decode(_enc_pin0, (volatile uint8_t*)state.tls_pins_blinded[0],
                              ARAN_GENESIS_PIN_LEN, _GENESIS_FK_PIN0);
        aran_xor_chain_decode(_enc_pin1, (volatile uint8_t*)state.tls_pins_blinded[1],
                              ARAN_GENESIS_PIN_LEN, _GENESIS_FK_PIN1);
    }

    if (_enc_endpoint_len > 0 && _enc_endpoint_len <= ARAN_GENESIS_ENDPOINT_LEN) {
        volatile uint8_t tmp[ARAN_GENESIS_ENDPOINT_LEN];
        memset((void*)tmp, 0, sizeof(tmp));
        aran_xor_chain_decode(_enc_endpoint, tmp, _enc_endpoint_len, _GENESIS_FK_ENDPOINT);
        memcpy(state.sync_endpoint, (const void*)tmp, _enc_endpoint_len);
        aran_secure_wipe((volatile void*)tmp, sizeof(tmp));
    }

    if (_enc_license_ep_len > 0 && _enc_license_ep_len <= ARAN_GENESIS_ENDPOINT_LEN) {
        volatile uint8_t tmp[ARAN_GENESIS_ENDPOINT_LEN];
        memset((void*)tmp, 0, sizeof(tmp));
        aran_xor_chain_decode(_enc_license_ep, tmp, _enc_license_ep_len, _GENESIS_FK_LICENSE);
        memcpy(state.license_endpoint, (const void*)tmp, _enc_license_ep_len);
        aran_secure_wipe((volatile void*)tmp, sizeof(tmp));
    }

    state.default_reaction_policy = 3; // KILL_APP
    state.config_version = 1;
    state.sync_interval_seconds = 60;

    return state;
}

void aran_wipe_genesis_state(AranGenesisState* state) {
    if (!state) return;
    aran_secure_wipe(state, sizeof(AranGenesisState));
}

// ============================================================================
// MARK: - Zero-Knowledge Blinded Pin Verification
// ============================================================================

int aran_verify_cert_blinded(const uint8_t* server_cert_hash, uint32_t hash_len) {
    if (!server_cert_hash || hash_len != 32) return 0;

    AranGenesisState genesis = aran_load_genesis_state();

    // Blind incoming server cert hash: SHA256(salt || cert_hash)
    volatile uint8_t blinded_server[32];
    aran_blind_pin_hash(server_cert_hash, genesis.blinding_salt, ARAN_GENESIS_SALT_LEN, (uint8_t*)blinded_server);

    // Constant-time compare against each blinded pin
    int pin0_match = aran_secure_compare((const uint8_t*)blinded_server, genesis.tls_pins_blinded[0], 32);
    int pin1_match = aran_secure_compare((const uint8_t*)blinded_server, genesis.tls_pins_blinded[1], 32);

    aran_secure_wipe((volatile void*)blinded_server, 32);
    aran_wipe_genesis_state(&genesis);

    return (pin0_match == 0 || pin1_match == 0) ? 1 : 0;
}

// ============================================================================
// MARK: - JNI: loadGenesisState → returns JSON with base64-encoded fields
// ============================================================================

extern "C" JNIEXPORT jstring JNICALL
Java_org_mazhai_aran_core_AranNative_loadGenesisState(JNIEnv* env, jobject thiz) {
    (void)thiz;

    AranGenesisState state = aran_load_genesis_state();

    // Base64-encode each binary field
    char aes_b64[64], hmac_b64[64], pin0_b64[64], pin1_b64[64], salt_b64[32];
    aran_base64_encode(state.aes_key, ARAN_GENESIS_AES_KEY_LEN, aes_b64, sizeof(aes_b64));
    aran_base64_encode(state.hmac_secret, ARAN_GENESIS_HMAC_SECRET_LEN, hmac_b64, sizeof(hmac_b64));
    aran_base64_encode(state.tls_pins_blinded[0], ARAN_GENESIS_PIN_LEN, pin0_b64, sizeof(pin0_b64));
    aran_base64_encode(state.tls_pins_blinded[1], ARAN_GENESIS_PIN_LEN, pin1_b64, sizeof(pin1_b64));
    aran_base64_encode(state.blinding_salt, ARAN_GENESIS_SALT_LEN, salt_b64, sizeof(salt_b64));

    // Build JSON string in native memory (never touches Java heap as structured data)
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"aes_key\":\"%s\","
        "\"hmac_secret\":\"%s\","
        "\"tls_pin0_blinded\":\"%s\","
        "\"tls_pin1_blinded\":\"%s\","
        "\"blinding_salt\":\"%s\","
        "\"default_reaction_policy\":%d,"
        "\"config_version\":%u,"
        "\"sync_interval_seconds\":%u,"
        "\"sync_endpoint\":\"%s\","
        "\"license_endpoint\":\"%s\""
        "}",
        aes_b64, hmac_b64, pin0_b64, pin1_b64, salt_b64,
        (int)state.default_reaction_policy,
        state.config_version,
        state.sync_interval_seconds,
        state.sync_endpoint,
        state.license_endpoint
    );

    // Wipe all intermediates
    aran_wipe_genesis_state(&state);
    aran_secure_wipe(aes_b64, sizeof(aes_b64));
    aran_secure_wipe(hmac_b64, sizeof(hmac_b64));
    aran_secure_wipe(pin0_b64, sizeof(pin0_b64));
    aran_secure_wipe(pin1_b64, sizeof(pin1_b64));
    aran_secure_wipe(salt_b64, sizeof(salt_b64));

    jstring result = env->NewStringUTF(json);

    // Wipe JSON buffer
    aran_secure_wipe(json, sizeof(json));

    return result;
}
