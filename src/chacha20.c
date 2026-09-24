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
// File:    chacha20.c
// Desc:    Implements the ChaCha20 stream cipher and HChaCha20 subkey
//          derivation used by the authenticated telemetry envelope.
// Created: 2026

#include "chacha20.h"

/**
 * @brief ChaCha20 state constant word zero, the ASCII bytes "expa".
 */
#define CHACHA20_CONST0 0x61707865u

/**
 * @brief ChaCha20 state constant word one, the ASCII bytes "nd 3".
 */
#define CHACHA20_CONST1 0x3320646eu

/**
 * @brief ChaCha20 state constant word two, the ASCII bytes "2-by".
 */
#define CHACHA20_CONST2 0x79622d32u

/**
 * @brief ChaCha20 state constant word three, the ASCII bytes "te k".
 */
#define CHACHA20_CONST3 0x6b206574u

/**
 * @brief Number of ChaCha20 double rounds that form the 20 round core.
 */
#define CHACHA20_DOUBLE_ROUNDS 10u

/**
 * @brief Rotate a 32-bit word left by a fixed count.
 *
 * @param value Input word.
 * @param count Rotation count in bits, never zero.
 * @return uint32_t Rotated word.
 */
static uint32_t chacha20_rotl(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32u - count));
}

/**
 * @brief Load a little-endian 32-bit word from four bytes.
 *
 * @param p Pointer to four readable bytes.
 * @return uint32_t Decoded word.
 */
static uint32_t chacha20_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

/**
 * @brief Store a 32-bit word as four little-endian bytes.
 *
 * @param p Pointer to four writable bytes.
 * @param value Word to encode.
 * @return void
 */
static void chacha20_store32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8u) & 0xffu);
    p[2] = (uint8_t)((value >> 16u) & 0xffu);
    p[3] = (uint8_t)((value >> 24u) & 0xffu);
}

/**
 * @brief Apply one ChaCha20 quarter round to four state words.
 *
 * @param a Pointer to the first state word.
 * @param b Pointer to the second state word.
 * @param c Pointer to the third state word.
 * @param d Pointer to the fourth state word.
 * @return void
 */
static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = chacha20_rotl(*d, 16u);
    *c += *d; *b ^= *c; *b = chacha20_rotl(*b, 12u);
    *a += *b; *d ^= *a; *d = chacha20_rotl(*d, 8u);
    *c += *d; *b ^= *c; *b = chacha20_rotl(*b, 7u);
}

/**
 * @brief Apply one ChaCha20 double round to the full state.
 *
 * @param x Pointer to the 16-word state.
 * @return void
 */
static void chacha20_double_round(uint32_t x[16]) {
    chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
    chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
    chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
    chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);
    chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
    chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
    chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
    chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
}

/**
 * @brief Run the 20-round ChaCha20 core over the state in place.
 *
 * @param x Pointer to the 16-word state.
 * @return void
 */
static void chacha20_rounds(uint32_t x[16]) {
    uint8_t i;
    for (i = 0u; i < CHACHA20_DOUBLE_ROUNDS; ++i) { chacha20_double_round(x); }
}

/**
 * @brief Load the eight key words into state words four through eleven.
 *
 * @param x Pointer to the 16-word state.
 * @param key Pointer to a 32-byte key.
 * @return void
 */
static void chacha20_load_key(uint32_t x[16], const uint8_t key[32]) {
    uint8_t i;
    for (i = 0u; i < 8u; ++i) { x[4u + i] = chacha20_load32(key + 4u * i); }
}

/**
 * @brief Load the 12-byte IETF nonce into state words thirteen through fifteen.
 *
 * @param x Pointer to the 16-word state.
 * @param nonce Pointer to the 12-byte IETF nonce.
 * @return void
 */
static void chacha20_load_nonce(uint32_t x[16], const uint8_t nonce[12]) {
    x[13] = chacha20_load32(nonce);
    x[14] = chacha20_load32(nonce + 4u);
    x[15] = chacha20_load32(nonce + 8u);
}

/**
 * @brief Build the standard ChaCha20 state from key, counter, and nonce.
 *
 * @param x Pointer to the 16-word state output.
 * @param key Pointer to a 32-byte key.
 * @param counter Block counter placed in state word twelve.
 * @param nonce Pointer to the 12-byte IETF nonce.
 * @return void
 */
static void chacha20_init_state(uint32_t x[16], const uint8_t key[32], uint32_t counter,
                                const uint8_t nonce[12]) {
    x[0] = CHACHA20_CONST0; x[1] = CHACHA20_CONST1;
    x[2] = CHACHA20_CONST2; x[3] = CHACHA20_CONST3;
    chacha20_load_key(x, key);
    x[12] = counter;
    chacha20_load_nonce(x, nonce);
}

/**
 * @brief Add the original state into the mixed state.
 *
 * @param x Pointer to the mixed 16-word state updated in place.
 * @param key Pointer to a 32-byte key.
 * @param counter Block counter used to build the state.
 * @param nonce Pointer to the 12-byte IETF nonce.
 * @return void
 */
static void chacha20_add_state(uint32_t x[16], const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12]) {
    uint32_t s[16];
    uint8_t i;
    chacha20_init_state(s, key, counter, nonce);
    for (i = 0u; i < 16u; ++i) { x[i] += s[i]; }
}

/**
 * @brief Serialize the mixed state to a little-endian keystream block.
 *
 * @param x Pointer to the 16-word mixed state.
 * @param out Pointer to a 64-byte keystream output buffer.
 * @return void
 */
static void chacha20_serialize(const uint32_t x[16], uint8_t out[64]) {
    uint8_t i;
    for (i = 0u; i < 16u; ++i) { chacha20_store32(out + 4u * i, x[i]); }
}

/**
 * @brief Build the HChaCha20 state from key and the 16-byte nonce.
 *
 * @param x Pointer to the 16-word state output.
 * @param key Pointer to a 32-byte key.
 * @param nonce Pointer to the 16-byte extended nonce.
 * @return void
 */
static void chacha20_init_hstate(uint32_t x[16], const uint8_t key[32], const uint8_t nonce[16]) {
    uint8_t i;
    x[0] = CHACHA20_CONST0; x[1] = CHACHA20_CONST1;
    x[2] = CHACHA20_CONST2; x[3] = CHACHA20_CONST3;
    chacha20_load_key(x, key);
    for (i = 0u; i < 4u; ++i) { x[12u + i] = chacha20_load32(nonce + 4u * i); }
}

/**
 * @brief Serialize the HChaCha20 subkey from state words 0..3 and 12..15.
 *
 * @param x Pointer to the 16-word mixed state.
 * @param out Pointer to a 32-byte subkey output buffer.
 * @return void
 */
static void chacha20_store_hout(const uint32_t x[16], uint8_t out[32]) {
    uint8_t i;
    for (i = 0u; i < 4u; ++i) { chacha20_store32(out + 4u * i, x[i]); }
    for (i = 0u; i < 4u; ++i) { chacha20_store32(out + 16u + 4u * i, x[12u + i]); }
}

/**
 * @brief XOR one keystream block into the output at a byte offset.
 *
 * @param in Pointer to the input bytes.
 * @param out Pointer to the output bytes (may alias in).
 * @param offset Byte offset of this block within the range.
 * @param len Total number of bytes to process.
 * @param block Pointer to the 64-byte keystream block.
 * @return void
 */
static void chacha20_xor_part(const uint8_t *in, uint8_t *out, size_t offset, size_t len,
                              const uint8_t block[64]) {
    size_t take = ((len - offset) < 64u) ? (len - offset) : 64u;
    size_t i;
    for (i = 0u; i < take; ++i) { out[offset + i] = (uint8_t)(in[offset + i] ^ block[i]); }
}

void chacha20_block(const uint8_t key[CHACHA20_KEY_LEN], uint32_t counter,
                    const uint8_t nonce[CHACHA20_NONCE_LEN], uint8_t out[CHACHA20_BLOCK_LEN]) {
    uint32_t x[16];
    chacha20_init_state(x, key, counter, nonce);
    chacha20_rounds(x);
    chacha20_add_state(x, key, counter, nonce);
    chacha20_serialize(x, out);
}

void hchacha20(const uint8_t key[CHACHA20_KEY_LEN], const uint8_t nonce[CHACHA20_HNONCE_LEN],
               uint8_t out[CHACHA20_KEY_LEN]) {
    uint32_t x[16];
    chacha20_init_hstate(x, key, nonce);
    chacha20_rounds(x);
    chacha20_store_hout(x, out);
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY_LEN], const uint8_t nonce[CHACHA20_NONCE_LEN],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[CHACHA20_BLOCK_LEN];
    size_t offset = 0u;
    while (offset < len) {
        chacha20_block(key, counter, nonce, block);
        chacha20_xor_part(in, out, offset, len, block);
        counter += 1u;
        offset += CHACHA20_BLOCK_LEN;
    }
}
