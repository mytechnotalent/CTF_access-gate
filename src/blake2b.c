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
// File:    blake2b.c
// Desc:    Implements unkeyed BLAKE2b and the Argon2 variable-length hash.
// Created: 2026

#include "blake2b.h"

/**
 * @brief BLAKE2b initialization vector.
 */
static const uint64_t g_blake2b_iv[8] = {
    0x6a09e667f3bcc908u, 0xbb67ae8584caa73bu, 0x3c6ef372fe94f82bu,
    0xa54ff53a5f1d36f1u, 0x510e527fade682d1u, 0x9b05688c2b3e6c1fu,
    0x1f83d9abfb41bd6bu, 0x5be0cd19137e2179u,
};

/**
 * @brief BLAKE2b message schedule permutations.
 */
static const uint8_t g_blake2b_sigma[12][16] = {
    {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u},
    {14u, 10u, 4u, 8u, 9u, 15u, 13u, 6u, 1u, 12u, 0u, 2u, 11u, 7u, 5u, 3u},
    {11u, 8u, 12u, 0u, 5u, 2u, 15u, 13u, 10u, 14u, 3u, 6u, 7u, 1u, 9u, 4u},
    {7u, 9u, 3u, 1u, 13u, 12u, 11u, 14u, 2u, 6u, 5u, 10u, 4u, 0u, 15u, 8u},
    {9u, 0u, 5u, 7u, 2u, 4u, 10u, 15u, 14u, 1u, 11u, 12u, 6u, 8u, 3u, 13u},
    {2u, 12u, 6u, 10u, 0u, 11u, 8u, 3u, 4u, 13u, 7u, 5u, 15u, 14u, 1u, 9u},
    {12u, 5u, 1u, 15u, 14u, 13u, 4u, 10u, 0u, 7u, 6u, 3u, 9u, 2u, 8u, 11u},
    {13u, 11u, 7u, 14u, 12u, 1u, 3u, 9u, 5u, 0u, 15u, 4u, 8u, 6u, 2u, 10u},
    {6u, 15u, 14u, 9u, 11u, 3u, 0u, 8u, 12u, 2u, 13u, 7u, 1u, 4u, 10u, 5u},
    {10u, 2u, 8u, 4u, 7u, 6u, 1u, 5u, 15u, 11u, 9u, 14u, 3u, 12u, 13u, 0u},
    {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u},
    {14u, 10u, 4u, 8u, 9u, 15u, 13u, 6u, 1u, 12u, 0u, 2u, 11u, 7u, 5u, 3u},
};

/**
 * @brief Chained 64-byte block shared by the variable-length hash.
 */
static uint8_t g_b2_hprime[BLAKE2B_OUT_LEN];

/**
 * @brief Store a 32-bit little-endian integer.
 *
 * @param p Pointer to four writable bytes.
 * @param x Value to store.
 * @return void
 */
static void b2_store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8u);
    p[2] = (uint8_t)(x >> 16u);
    p[3] = (uint8_t)(x >> 24u);
}

/**
 * @brief Load a 64-bit little-endian integer.
 *
 * @param p Pointer to eight readable bytes.
 * @return uint64_t Loaded value.
 */
static uint64_t b2_load_le64(const uint8_t *p) {
    uint64_t x = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        x |= (uint64_t)p[i] << (8u * i);
    }
    return x;
}

/**
 * @brief Copy a byte range.
 *
 * @param dst Pointer to the destination bytes.
 * @param src Pointer to the source bytes.
 * @param len Number of bytes to copy.
 * @return void
 */
static void b2_copy(uint8_t *dst, const uint8_t *src, uint32_t len) {
    uint32_t i;
    for (i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

/**
 * @brief Rotate a 64-bit word to the right.
 *
 * @param x Word to rotate.
 * @param n Rotation distance in bits.
 * @return uint64_t Rotated word.
 */
static uint64_t b2_rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64u - n));
}

/**
 * @brief Apply the BLAKE2b G mixing function to four state words.
 *
 * @param v Pointer to the 16-word working state.
 * @param m Pointer to the 16-word message block.
 * @param a Index of the first state word.
 * @param b Index of the second state word.
 * @param c Index of the third state word.
 * @param d Index of the fourth state word.
 * @param x Index of the first message word.
 * @param y Index of the second message word.
 * @return void
 */
static void b2_mix(uint64_t *v, const uint64_t *m, uint32_t a, uint32_t b,
                   uint32_t c, uint32_t d, uint32_t x, uint32_t y) {
    v[a] = v[a] + v[b] + m[x];
    v[d] = b2_rotr64(v[d] ^ v[a], 32u);
    v[c] = v[c] + v[d];
    v[b] = b2_rotr64(v[b] ^ v[c], 24u);
    v[a] = v[a] + v[b] + m[y];
    v[d] = b2_rotr64(v[d] ^ v[a], 16u);
    v[c] = v[c] + v[d];
    v[b] = b2_rotr64(v[b] ^ v[c], 63u);
}

/**
 * @brief Apply one full BLAKE2b round using a sigma schedule row.
 *
 * @param v Pointer to the 16-word working state.
 * @param m Pointer to the 16-word message block.
 * @param s Pointer to the sixteen sigma indices for this round.
 * @return void
 */
static void b2_round(uint64_t *v, const uint64_t *m, const uint8_t *s) {
    b2_mix(v, m, 0u, 4u, 8u, 12u, s[0], s[1]);
    b2_mix(v, m, 1u, 5u, 9u, 13u, s[2], s[3]);
    b2_mix(v, m, 2u, 6u, 10u, 14u, s[4], s[5]);
    b2_mix(v, m, 3u, 7u, 11u, 15u, s[6], s[7]);
    b2_mix(v, m, 0u, 5u, 10u, 15u, s[8], s[9]);
    b2_mix(v, m, 1u, 6u, 11u, 12u, s[10], s[11]);
    b2_mix(v, m, 2u, 7u, 8u, 13u, s[12], s[13]);
    b2_mix(v, m, 3u, 4u, 9u, 14u, s[14], s[15]);
}

/**
 * @brief Load a 128-byte block into sixteen little-endian message words.
 *
 * @param m Pointer to the message word output array.
 * @param block Pointer to the 128 readable block bytes.
 * @return void
 */
static void b2_load_block(uint64_t *m, const uint8_t *block) {
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        m[i] = b2_load_le64(block + 8u * i);
    }
}

/**
 * @brief Initialize the BLAKE2b working vector for one block.
 *
 * @param v Pointer to the 16-word working state.
 * @param ctx Pointer to the streaming state.
 * @param last True when compressing the final block.
 * @return void
 */
static void b2_init_v(uint64_t *v, const blake2b_ctx_t *ctx, bool last) {
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        v[i] = ctx->h[i];
        v[i + 8u] = g_blake2b_iv[i];
    }
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (last) {
        v[14] = ~v[14];
    }
}

/**
 * @brief Apply all BLAKE2b rounds to the working vector.
 *
 * @param v Pointer to the 16-word working state.
 * @param m Pointer to the 16-word message block.
 * @return void
 */
static void b2_rounds(uint64_t *v, const uint64_t *m) {
    uint32_t i;
    for (i = 0u; i < BLAKE2B_ROUNDS; ++i) {
        b2_round(v, m, g_blake2b_sigma[i]);
    }
}

/**
 * @brief Fold the working vector back into the chaining state.
 *
 * @param ctx Pointer to the streaming state.
 * @param v Pointer to the 16-word working state.
 * @return void
 */
static void b2_fold(blake2b_ctx_t *ctx, const uint64_t *v) {
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        ctx->h[i] ^= v[i] ^ v[i + 8u];
    }
}

/**
 * @brief Compress one 128-byte block into the chaining state.
 *
 * @param ctx Pointer to the streaming state.
 * @param block Pointer to the 128 readable block bytes.
 * @param last True when compressing the final block.
 * @return void
 */
static void b2_compress(blake2b_ctx_t *ctx, const uint8_t *block, bool last) {
    uint64_t v[16];
    uint64_t m[16];
    b2_load_block(m, block);
    b2_init_v(v, ctx, last);
    b2_rounds(v, m);
    b2_fold(ctx, v);
}

/**
 * @brief Zero the unused tail of the pending block buffer.
 *
 * @param ctx Pointer to the streaming state.
 * @return void
 */
static void blake2b_zero_pad(blake2b_ctx_t *ctx) {
    uint32_t i;
    for (i = ctx->buflen; i < BLAKE2B_BLOCK_LEN; ++i) {
        ctx->buf[i] = 0u;
    }
}

void blake2b_init(blake2b_ctx_t *ctx, uint32_t out_len) {
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        ctx->h[i] = g_blake2b_iv[i];
    }
    ctx->h[0] ^= 0x01010000u ^ out_len;
    ctx->t[0] = 0u;
    ctx->t[1] = 0u;
    ctx->buflen = 0u;
    ctx->outlen = out_len;
}

/**
 * @brief Compress a full pending block, keeping the final block buffered.
 *
 * @param ctx Pointer to the streaming state.
 * @return void
 */
static void b2_flush_full(blake2b_ctx_t *ctx) {
    if (ctx->buflen == BLAKE2B_BLOCK_LEN) {
        ctx->t[0] += BLAKE2B_BLOCK_LEN;
        b2_compress(ctx, ctx->buf, false);
        ctx->buflen = 0u;
    }
}

void blake2b_update(blake2b_ctx_t *ctx, const uint8_t *in, size_t in_len) {
    size_t i;
    for (i = 0u; i < in_len; ++i) {
        b2_flush_full(ctx);
        ctx->buf[ctx->buflen] = in[i];
        ctx->buflen += 1u;
    }
}

void blake2b_final(blake2b_ctx_t *ctx, uint8_t *out) {
    uint32_t i;
    blake2b_zero_pad(ctx);
    ctx->t[0] += ctx->buflen;
    b2_compress(ctx, ctx->buf, true);
    for (i = 0u; i < ctx->outlen; ++i) {
        out[i] = (uint8_t)(ctx->h[i / 8u] >> (8u * (i % 8u)));
    }
}

void blake2b_hash(uint8_t *out, uint32_t out_len, const uint8_t *in,
                  size_t in_len) {
    blake2b_ctx_t ctx;
    blake2b_init(&ctx, out_len);
    blake2b_update(&ctx, in, in_len);
    blake2b_final(&ctx, out);
}

/**
 * @brief Compute one prefixed BLAKE2b block for H'.
 *
 * @param out Pointer to the digest output buffer.
 * @param digest_len Requested digest length in bytes.
 * @param prefix_len Length value stored as a little-endian prefix.
 * @param in Pointer to readable input bytes.
 * @param in_len Number of input bytes.
 * @return void
 */
static void hprime_mix(uint8_t *out, uint32_t digest_len, uint32_t prefix_len,
                       const uint8_t *in, size_t in_len) {
    uint8_t lenbuf[4];
    blake2b_ctx_t ctx;
    b2_store_le32(lenbuf, prefix_len);
    blake2b_init(&ctx, digest_len);
    blake2b_update(&ctx, lenbuf, 4u);
    blake2b_update(&ctx, in, in_len);
    blake2b_final(&ctx, out);
}

/**
 * @brief Chain one 64-byte block of the variable-length hash.
 *
 * @param out Pointer to the digest output buffer.
 * @param digest_len Requested digest length in bytes.
 * @param in Pointer to the 64 readable input bytes.
 * @return void
 */
static void hprime_chain(uint8_t *out, uint32_t digest_len, const uint8_t *in) {
    blake2b_ctx_t ctx;
    blake2b_init(&ctx, digest_len);
    blake2b_update(&ctx, in, BLAKE2B_OUT_LEN);
    blake2b_final(&ctx, out);
}

/**
 * @brief Emit the chained part of a long variable-length hash.
 *
 * @param out Pointer to the output buffer.
 * @param out_len Total requested output length in bytes.
 * @return void
 */
static void b2_long_chain(uint8_t *out, uint32_t out_len) {
    uint32_t off = 32u;
    b2_copy(out, g_b2_hprime, 32u);
    while (out_len - off > BLAKE2B_OUT_LEN) {
        hprime_chain(g_b2_hprime, BLAKE2B_OUT_LEN, g_b2_hprime);
        b2_copy(out + off, g_b2_hprime, 32u);
        off += 32u;
    }
    hprime_chain(g_b2_hprime, out_len - off, g_b2_hprime);
    b2_copy(out + off, g_b2_hprime, out_len - off);
}

void blake2b_long(uint8_t *out, uint32_t out_len, const uint8_t *in,
                  size_t in_len) {
    if (out_len <= BLAKE2B_OUT_LEN) {
        hprime_mix(out, out_len, out_len, in, in_len);
        return;
    }
    hprime_mix(g_b2_hprime, BLAKE2B_OUT_LEN, out_len, in, in_len);
    b2_long_chain(out, out_len);
}
