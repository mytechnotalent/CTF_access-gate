// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/cold-chain-monitor-c-rp2350
// File:    envelope.c
// Desc:    Implements the hex XChaCha20-Poly1305 telemetry envelope codec
//          with strict lowercase encoding and constant-time authentication.
// Created: 2026

#include "envelope.h"

#include "crypto_aead.h"
#include "pico/rand.h"

#include <string.h>

/**
 * @brief Return the lowercase hex digit for a nibble value.
 *
 * @param v Nibble value in the range zero to fifteen.
 * @return char Lowercase hexadecimal ASCII digit.
 */
static char nibble_to_hex(uint8_t v) {
    return (v < 10u) ? (char)('0' + v) : (char)('a' + (v - 10u));
}

/**
 * @brief Return the numeric value of one hexadecimal ASCII digit.
 *
 * @param c Input character.
 * @return int Digit value, or -1 when the character is not hexadecimal.
 */
static int hex_val(char c) {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/**
 * @brief Decode one hexadecimal ASCII digit into a nibble.
 *
 * @param c Input character.
 * @param out Pointer to store the decoded nibble.
 * @return bool true when the character decoded.
 */
static bool hex_to_nibble(char c, uint8_t *out) {
    int v = hex_val(c);
    if (v < 0) {
        return false;
    }
    *out = (uint8_t)v;
    return true;
}

/**
 * @brief Encode a byte buffer as a lowercase hex string.
 *
 * @param in Pointer to the input bytes.
 * @param n Number of input bytes.
 * @param out Pointer to the NUL-terminated hex output buffer.
 * @return void
 */
static void bytes_to_hex(const uint8_t *in, size_t n, char *out) {
    size_t i;
    for (i = 0u; i < n; ++i) {
        out[i * 2u] = nibble_to_hex((uint8_t)(in[i] >> 4));
        out[i * 2u + 1u] = nibble_to_hex((uint8_t)(in[i] & 0x0Fu));
    }
    out[n * 2u] = '\0';
}

/**
 * @brief Decode a complete even-length hex string into bytes.
 *
 * @param hex Pointer to the NUL-terminated hex string.
 * @param hex_len Number of hex characters.
 * @param out Pointer to the decoded byte output buffer.
 * @return bool true when every character decoded.
 */
static bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out) {
    size_t i;
    for (i = 0u; i < hex_len; i += 2u) {
        uint8_t hi;
        uint8_t lo;
        if (!hex_to_nibble(hex[i], &hi) || !hex_to_nibble(hex[i + 1u], &lo)) {
            return false;
        }
        out[i / 2u] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/**
 * @brief Assemble the nonce || ciphertext || tag binary envelope.
 *
 * @param key Pointer to a 32-byte session key.
 * @param nonce Pointer to the 24-byte unique nonce.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param pt Pointer to the plaintext bytes.
 * @param pt_len Number of plaintext bytes.
 * @param env Pointer to the binary envelope output buffer.
 * @return void
 */
static void seal_envelope(const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t ad_len, const uint8_t *pt, size_t pt_len, uint8_t *env) {
    uint8_t ct[ENVELOPE_MAX_PLAINTEXT];
    uint8_t tag[ENVELOPE_TAG_LEN];
    crypto_aead_seal(key, nonce, ad, ad_len, pt, pt_len, ct, tag);
    memcpy(env, nonce, ENVELOPE_NONCE_LEN);
    memcpy(env + ENVELOPE_NONCE_LEN, ct, pt_len);
    memcpy(env + ENVELOPE_NONCE_LEN + pt_len, tag, ENVELOPE_TAG_LEN);
}

/**
 * @brief Decode and bound-check a hex envelope into a raw buffer.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param raw Pointer to the decoded byte output buffer.
 * @param raw_cap Capacity of the raw output buffer in bytes.
 * @param raw_len Pointer to store the decoded byte length.
 * @return bool true when the hex was even, long enough, and in bounds.
 */
static bool decode_envelope(const char *hex, uint8_t *raw, size_t raw_cap, size_t *raw_len) {
    size_t hex_len = strlen(hex);
    if ((hex_len % 2u) != 0u || hex_len < (ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN) * 2u) {
        return false;
    }
    *raw_len = hex_len / 2u;
    if (*raw_len > raw_cap) {
        return false;
    }
    return hex_to_bytes(hex, hex_len, raw);
}

/**
 * @brief Verify and decrypt one bounded binary envelope.
 *
 * @param key Pointer to a 32-byte session key.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param raw Pointer to the decoded binary envelope.
 * @param raw_len Number of decoded envelope bytes.
 * @param pt_out Pointer to the plaintext output buffer.
 * @param pt_out_len Capacity of the plaintext output buffer in bytes.
 * @param pt_len Pointer to store the recovered plaintext length.
 * @return bool true when the tag verified and plaintext was produced.
 */
static bool open_envelope(const uint8_t key[32], const uint8_t *ad, size_t ad_len, const uint8_t *raw, size_t raw_len, uint8_t *pt_out, size_t pt_out_len, size_t *pt_len) {
    size_t ct_len = raw_len - ENVELOPE_NONCE_LEN - ENVELOPE_TAG_LEN;
    if (pt_out_len < ct_len) {
        return false;
    }
    if (!crypto_aead_open(key, raw, ad, ad_len, raw + ENVELOPE_NONCE_LEN, ct_len, raw + ENVELOPE_NONCE_LEN + ct_len, pt_out)) {
        return false;
    }
    *pt_len = ct_len;
    return true;
}

void envelope_fill_nonce(uint8_t nonce[ENVELOPE_NONCE_LEN]) {
    size_t i;
    for (i = 0u; i < ENVELOPE_NONCE_LEN; i += 4u) {
        uint32_t word = get_rand_32();
        nonce[i] = (uint8_t)(word & 0xFFu);
        nonce[i + 1u] = (uint8_t)((word >> 8) & 0xFFu);
        nonce[i + 2u] = (uint8_t)((word >> 16) & 0xFFu);
        nonce[i + 3u] = (uint8_t)((word >> 24) & 0xFFu);
    }
}

bool envelope_seal_hex(const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t ad_len, const uint8_t *pt, size_t pt_len, char *out, size_t out_len) {
    uint8_t envelope[ENVELOPE_NONCE_LEN + ENVELOPE_MAX_PLAINTEXT + ENVELOPE_TAG_LEN];
    size_t total_len = ENVELOPE_NONCE_LEN + pt_len + ENVELOPE_TAG_LEN;
    if (pt_len > ENVELOPE_MAX_PLAINTEXT || out_len < (total_len * 2u + 1u)) {
        return false;
    }
    seal_envelope(key, nonce, ad, ad_len, pt, pt_len, envelope);
    bytes_to_hex(envelope, total_len, out);
    return true;
}

bool envelope_open_hex(const uint8_t key[32], const uint8_t *ad, size_t ad_len, const char *hex, uint8_t *pt_out, size_t pt_out_len, size_t *pt_len) {
    uint8_t raw[ENVELOPE_NONCE_LEN + ENVELOPE_MAX_PLAINTEXT + ENVELOPE_TAG_LEN];
    size_t raw_len;
    if (!decode_envelope(hex, raw, sizeof(raw), &raw_len)) {
        return false;
    }
    return open_envelope(key, ad, ad_len, raw, raw_len, pt_out, pt_out_len, pt_len);
}
