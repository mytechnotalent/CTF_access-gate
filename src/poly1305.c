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
// File:    poly1305.c
// Desc:    Implements the Poly1305 one-time message authenticator and the
//          AEAD message framing that feeds it.
// Created: 2026

#include "poly1305.h"

/**
 * @brief Poly1305 block size in bytes.
 */
#define POLY1305_BLOCK_LEN 16u

/**
 * @brief Poly1305 limb width in bits.
 */
#define POLY1305_LIMB_BITS 26u

/**
 * @brief Poly1305 mask that keeps one 26-bit limb.
 */
#define POLY1305_LIMB_MASK 0x3ffffffu

/**
 * @brief Poly1305 high bit added to every full message block.
 */
#define POLY1305_HIBIT 0x1000000u

/**
 * @brief Streaming Poly1305 accumulator state.
 */
typedef struct poly1305_stream {
    /**
     * @brief Accumulator limbs h0 through h4.
     */
    uint32_t h[5];
    /**
     * @brief Clamped one-time key limbs r0 through r4.
     */
    uint32_t r[5];
    /**
     * @brief Second half of the one-time key added at the end.
     */
    uint32_t s[4];
    /**
     * @brief Pending partial block bytes.
     */
    uint8_t buf[POLY1305_BLOCK_LEN];
    /**
     * @brief Number of pending bytes held in buf.
     */
    size_t buf_len;
} poly1305_stream_t;

/**
 * @brief Load a little-endian 32-bit word from four bytes.
 *
 * @param p Pointer to four readable bytes.
 * @return uint32_t Decoded word.
 */
static uint32_t poly1305_load32(const uint8_t *p) {
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
static void poly1305_store32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8u) & 0xffu);
    p[2] = (uint8_t)((value >> 16u) & 0xffu);
    p[3] = (uint8_t)((value >> 24u) & 0xffu);
}

/**
 * @brief Store a 64-bit value as eight little-endian bytes.
 *
 * @param p Pointer to eight writable bytes.
 * @param value Value to encode.
 * @return void
 */
static void poly1305_store64(uint8_t *p, uint64_t value) {
    poly1305_store32(p, (uint32_t)(value & 0xffffffffu));
    poly1305_store32(p + 4u, (uint32_t)(value >> 32u));
}

/**
 * @brief Copy bytes from one buffer to another.
 *
 * @param dst Pointer to the destination buffer.
 * @param src Pointer to the source buffer.
 * @param len Number of bytes to copy.
 * @return void
 */
static void poly1305_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    size_t i;
    for (i = 0u; i < len; ++i) { dst[i] = src[i]; }
}

/**
 * @brief Write zero bytes across a buffer.
 *
 * @param dst Pointer to the destination buffer.
 * @param len Number of bytes to clear.
 * @return void
 */
static void poly1305_zero(uint8_t *dst, size_t len) {
    size_t i;
    for (i = 0u; i < len; ++i) { dst[i] = 0u; }
}

/**
 * @brief Load and clamp the r half of the one-time key.
 *
 * @param st Pointer to the streaming state.
 * @param key Pointer to a 32-byte one-time key.
 * @return void
 */
static void poly1305_set_r(poly1305_stream_t *st, const uint8_t *key) {
    st->r[0] = poly1305_load32(key) & POLY1305_LIMB_MASK;
    st->r[1] = (poly1305_load32(key + 3u) >> 2u) & 0x3ffff03u;
    st->r[2] = (poly1305_load32(key + 6u) >> 4u) & 0x3ffc0ffu;
    st->r[3] = (poly1305_load32(key + 9u) >> 6u) & 0x3f03fffu;
    st->r[4] = (poly1305_load32(key + 12u) >> 8u) & 0x00fffffu;
}

/**
 * @brief Load the s half of the one-time key into four words.
 *
 * @param st Pointer to the streaming state.
 * @param pad Pointer to the 16-byte s half of the key.
 * @return void
 */
static void poly1305_set_s(poly1305_stream_t *st, const uint8_t *pad) {
    st->s[0] = poly1305_load32(pad);
    st->s[1] = poly1305_load32(pad + 4u);
    st->s[2] = poly1305_load32(pad + 8u);
    st->s[3] = poly1305_load32(pad + 12u);
}

/**
 * @brief Initialize the accumulator and clamp the one-time key.
 *
 * @param st Pointer to the streaming state.
 * @param key Pointer to a 32-byte one-time key.
 * @return void
 */
static void poly1305_init(poly1305_stream_t *st, const uint8_t key[POLY1305_KEY_LEN]) {
    uint8_t i;
    for (i = 0u; i < 5u; ++i) { st->h[i] = 0u; }
    poly1305_set_r(st, key);
    poly1305_set_s(st, key + 16u);
    st->buf_len = 0u;
}

/**
 * @brief Add one 16-byte little-endian block into the accumulator.
 *
 * @param st Pointer to the streaming state.
 * @param block Pointer to the 16-byte message block.
 * @param hibit High bit value to OR into the top limb.
 * @return void
 */
static void poly1305_add_block(poly1305_stream_t *st, const uint8_t *block, uint32_t hibit) {
    st->h[0] += poly1305_load32(block) & POLY1305_LIMB_MASK;
    st->h[1] += (poly1305_load32(block + 3u) >> 2u) & POLY1305_LIMB_MASK;
    st->h[2] += (poly1305_load32(block + 6u) >> 4u) & POLY1305_LIMB_MASK;
    st->h[3] += (poly1305_load32(block + 9u) >> 6u) & POLY1305_LIMB_MASK;
    st->h[4] += (poly1305_load32(block + 12u) >> 8u) | hibit;
}

/**
 * @brief Multiply the accumulator by r modulo 2^130 minus 5.
 *
 * @param h Pointer to the five accumulator limbs.
 * @param r Pointer to the five clamped key limbs.
 * @param d Pointer to five 64-bit products output.
 * @return void
 */
static void poly1305_mul_wide(const uint32_t h[5], const uint32_t r[5], uint64_t d[5]) {
    uint32_t s1 = r[1] * 5u; uint32_t s2 = r[2] * 5u;
    uint32_t s3 = r[3] * 5u; uint32_t s4 = r[4] * 5u;
    d[0] = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * s4 + (uint64_t)h[2] * s3 + (uint64_t)h[3] * s2 + (uint64_t)h[4] * s1;
    d[1] = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * s4 + (uint64_t)h[3] * s3 + (uint64_t)h[4] * s2;
    d[2] = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] + (uint64_t)h[3] * s4 + (uint64_t)h[4] * s3;
    d[3] = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] + (uint64_t)h[4] * s4;
    d[4] = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];
}

/**
 * @brief Carry the wide products back into 26-bit accumulator limbs.
 *
 * @param d Pointer to the five wide product limbs.
 * @param h Pointer to the five accumulator limbs output.
 * @return void
 */
static void poly1305_reduce(uint64_t d[5], uint32_t h[5]) {
    uint64_t c = d[0] >> POLY1305_LIMB_BITS; h[0] = (uint32_t)(d[0] & POLY1305_LIMB_MASK);
    d[1] += c; c = d[1] >> POLY1305_LIMB_BITS; h[1] = (uint32_t)(d[1] & POLY1305_LIMB_MASK);
    d[2] += c; c = d[2] >> POLY1305_LIMB_BITS; h[2] = (uint32_t)(d[2] & POLY1305_LIMB_MASK);
    d[3] += c; c = d[3] >> POLY1305_LIMB_BITS; h[3] = (uint32_t)(d[3] & POLY1305_LIMB_MASK);
    d[4] += c; c = d[4] >> POLY1305_LIMB_BITS; h[4] = (uint32_t)(d[4] & POLY1305_LIMB_MASK);
    h[0] += (uint32_t)(c * 5u); c = h[0] >> POLY1305_LIMB_BITS; h[0] &= POLY1305_LIMB_MASK;
    h[1] += (uint32_t)c;
}

/**
 * @brief Absorb one full 16-byte block into the accumulator.
 *
 * @param st Pointer to the streaming state.
 * @param block Pointer to the 16-byte message block.
 * @param hibit High bit value to OR into the top limb.
 * @return void
 */
static void poly1305_block(poly1305_stream_t *st, const uint8_t *block, uint32_t hibit) {
    uint64_t d[5];
    poly1305_add_block(st, block, hibit);
    poly1305_mul_wide(st->h, st->r, d);
    poly1305_reduce(d, st->h);
}

/**
 * @brief Fill the pending block from input and absorb it when full.
 *
 * @param st Pointer to the streaming state.
 * @param msg Pointer to the input bytes.
 * @param len Number of input bytes available.
 * @return size_t Number of bytes consumed.
 */
static size_t poly1305_absorb(poly1305_stream_t *st, const uint8_t *msg, size_t len) {
    size_t take = POLY1305_BLOCK_LEN - st->buf_len;
    if (take > len) { take = len; }
    poly1305_copy(st->buf + st->buf_len, msg, take);
    st->buf_len += take;
    if (st->buf_len == POLY1305_BLOCK_LEN) {
        poly1305_block(st, st->buf, POLY1305_HIBIT);
        st->buf_len = 0u;
    }
    return take;
}

/**
 * @brief Feed an arbitrary byte range into the accumulator.
 *
 * @param st Pointer to the streaming state.
 * @param msg Pointer to the input bytes.
 * @param len Number of input bytes.
 * @return void
 */
static void poly1305_update(poly1305_stream_t *st, const uint8_t *msg, size_t len) {
    size_t i = 0u;
    while (i < len) { i += poly1305_absorb(st, msg + i, len - i); }
}

/**
 * @brief Pad a segment with zero bytes to a 16-byte boundary.
 *
 * @param st Pointer to the streaming state.
 * @param len Length of the segment that was just fed.
 * @return void
 */
static void poly1305_pad16(poly1305_stream_t *st, size_t len) {
    const uint8_t zeros[POLY1305_BLOCK_LEN] = {0};
    size_t rem = len % POLY1305_BLOCK_LEN;
    if (rem != 0u) { poly1305_update(st, zeros, POLY1305_BLOCK_LEN - rem); }
}

/**
 * @brief Feed the little-endian associated-data and ciphertext lengths.
 *
 * @param st Pointer to the streaming state.
 * @param ad_len Number of associated-data bytes.
 * @param ct_len Number of ciphertext bytes.
 * @return void
 */
static void poly1305_lengths(poly1305_stream_t *st, size_t ad_len, size_t ct_len) {
    uint8_t block[POLY1305_BLOCK_LEN] = {0};
    poly1305_store64(block, (uint64_t)ad_len);
    poly1305_store64(block + 8u, (uint64_t)ct_len);
    poly1305_update(st, block, POLY1305_BLOCK_LEN);
}

/**
 * @brief Fully carry the accumulator to canonical 26-bit limbs.
 *
 * @param h Pointer to the five accumulator limbs.
 * @return void
 */
static void poly1305_carry_full(uint32_t h[5]) {
    uint32_t c = h[1] >> POLY1305_LIMB_BITS; h[1] &= POLY1305_LIMB_MASK;
    h[2] += c; c = h[2] >> POLY1305_LIMB_BITS; h[2] &= POLY1305_LIMB_MASK;
    h[3] += c; c = h[3] >> POLY1305_LIMB_BITS; h[3] &= POLY1305_LIMB_MASK;
    h[4] += c; c = h[4] >> POLY1305_LIMB_BITS; h[4] &= POLY1305_LIMB_MASK;
    h[0] += c * 5u; c = h[0] >> POLY1305_LIMB_BITS; h[0] &= POLY1305_LIMB_MASK;
    h[1] += c;
}

/**
 * @brief Compute the candidate accumulator minus the field prime.
 *
 * @param h Pointer to the five accumulator limbs.
 * @param g Pointer to the five candidate limbs output.
 * @return void
 */
static void poly1305_sub_p(const uint32_t h[5], uint32_t g[5]) {
    uint32_t c;
    g[0] = h[0] + 5u; c = g[0] >> POLY1305_LIMB_BITS; g[0] &= POLY1305_LIMB_MASK;
    g[1] = h[1] + c; c = g[1] >> POLY1305_LIMB_BITS; g[1] &= POLY1305_LIMB_MASK;
    g[2] = h[2] + c; c = g[2] >> POLY1305_LIMB_BITS; g[2] &= POLY1305_LIMB_MASK;
    g[3] = h[3] + c; c = g[3] >> POLY1305_LIMB_BITS; g[3] &= POLY1305_LIMB_MASK;
    g[4] = h[4] + c - (1u << POLY1305_LIMB_BITS);
}

/**
 * @brief Select the reduced candidate when the accumulator reached the prime.
 *
 * @param h Pointer to the five accumulator limbs updated in place.
 * @param g Pointer to the five candidate limbs.
 * @param mask All-ones to choose g, zero to keep h.
 * @return void
 */
static void poly1305_choose(uint32_t h[5], const uint32_t g[5], uint32_t mask) {
    uint8_t i;
    for (i = 0u; i < 5u; ++i) { h[i] = (h[i] & ~mask) | (g[i] & mask); }
}

/**
 * @brief Serialize the accumulator limbs into 16 little-endian bytes.
 *
 * @param h Pointer to the five accumulator limbs.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return void
 */
static void poly1305_serialize(const uint32_t h[5], uint8_t tag[POLY1305_TAG_LEN]) {
    uint32_t w[4];
    uint8_t i;
    w[0] = h[0] | (h[1] << 26u);
    w[1] = (h[1] >> 6u) | (h[2] << 20u);
    w[2] = (h[2] >> 12u) | (h[3] << 14u);
    w[3] = (h[3] >> 18u) | (h[4] << 8u);
    for (i = 0u; i < 4u; ++i) { poly1305_store32(tag + 4u * i, w[i]); }
}

/**
 * @brief Add the s half of the key to the serialized tag modulo 2^128.
 *
 * @param tag Pointer to the 16-byte tag updated in place.
 * @param s Pointer to the four s words.
 * @return void
 */
static void poly1305_add_pad(uint8_t tag[POLY1305_TAG_LEN], const uint32_t s[4]) {
    uint64_t carry = 0u;
    uint8_t i;
    for (i = 0u; i < 4u; ++i) {
        uint64_t sum = (uint64_t)poly1305_load32(tag + 4u * i) + s[i] + carry;
        poly1305_store32(tag + 4u * i, (uint32_t)sum);
        carry = sum >> 32u;
    }
}

/**
 * @brief Reduce the accumulator, add the key pad, and emit the tag.
 *
 * @param st Pointer to the streaming state.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return void
 */
static void poly1305_emit(poly1305_stream_t *st, uint8_t tag[POLY1305_TAG_LEN]) {
    uint32_t g[5];
    poly1305_carry_full(st->h);
    poly1305_sub_p(st->h, g);
    poly1305_choose(st->h, g, (g[4] >> 31u) - 1u);
    poly1305_serialize(st->h, tag);
    poly1305_add_pad(tag, st->s);
}

/**
 * @brief Absorb any trailing partial block and finish the accumulator.
 *
 * @param st Pointer to the streaming state.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return void
 */
static void poly1305_final(poly1305_stream_t *st, uint8_t tag[POLY1305_TAG_LEN]) {
    if (st->buf_len != 0u) {
        st->buf[st->buf_len] = 1u;
        poly1305_zero(st->buf + st->buf_len + 1u, POLY1305_BLOCK_LEN - st->buf_len - 1u);
        poly1305_block(st, st->buf, 0u);
    }
    poly1305_emit(st, tag);
}

void poly1305_mac(const uint8_t key[POLY1305_KEY_LEN], const uint8_t *msg, size_t len,
                  uint8_t tag[POLY1305_TAG_LEN]) {
    poly1305_stream_t st;
    poly1305_init(&st, key);
    poly1305_update(&st, msg, len);
    poly1305_final(&st, tag);
}

void poly1305_mac_aead(const uint8_t key[POLY1305_KEY_LEN], const uint8_t *ad, size_t ad_len,
                       const uint8_t *ct, size_t ct_len, uint8_t tag[POLY1305_TAG_LEN]) {
    poly1305_stream_t st;
    poly1305_init(&st, key);
    poly1305_update(&st, ad, ad_len);
    poly1305_pad16(&st, ad_len);
    poly1305_update(&st, ct, ct_len);
    poly1305_pad16(&st, ct_len);
    poly1305_lengths(&st, ad_len, ct_len);
    poly1305_final(&st, tag);
}
