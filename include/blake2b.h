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
// File:    blake2b.h
// Desc:    Declares unkeyed BLAKE2b and the Argon2 variable-length hash H'.
// Created: 2026

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief BLAKE2b maximum digest length in bytes.
 */
#define BLAKE2B_OUT_LEN 64u

/**
 * @brief BLAKE2b internal block length in bytes.
 */
#define BLAKE2B_BLOCK_LEN 128u

/**
 * @brief Number of compression rounds per BLAKE2b block.
 */
#define BLAKE2B_ROUNDS 12u

/**
 * @brief Streaming BLAKE2b state used by the Argon2 pre-hash.
 */
typedef struct blake2b_ctx {
    /**
     * @brief Chaining state words.
     */
    uint64_t h[8];
    /**
     * @brief 128-bit byte counter as two 64-bit halves.
     */
    uint64_t t[2];
    /**
     * @brief Pending input block buffer.
     */
    uint8_t buf[BLAKE2B_BLOCK_LEN];
    /**
     * @brief Number of pending bytes held in the block buffer.
     */
    uint32_t buflen;
    /**
     * @brief Requested digest length in bytes.
     */
    uint32_t outlen;
} blake2b_ctx_t;

/**
 * @brief Initialize an unkeyed BLAKE2b streaming state.
 *
 * @param ctx Pointer to the state to initialize.
 * @param out_len Requested digest length in bytes.
 * @return void
 */
void blake2b_init(blake2b_ctx_t *ctx, uint32_t out_len);

/**
 * @brief Absorb more input bytes into a BLAKE2b state.
 *
 * @param ctx Pointer to the streaming state.
 * @param in Pointer to readable input bytes.
 * @param in_len Number of input bytes to absorb.
 * @return void
 */
void blake2b_update(blake2b_ctx_t *ctx, const uint8_t *in, size_t in_len);

/**
 * @brief Finalize a BLAKE2b state and write the digest.
 *
 * @param ctx Pointer to the streaming state.
 * @param out Pointer to the digest output buffer.
 * @return void
 */
void blake2b_final(blake2b_ctx_t *ctx, uint8_t *out);

/**
 * @brief Compute an unkeyed BLAKE2b digest of a byte range.
 *
 * @param out Pointer to the digest output buffer.
 * @param out_len Requested digest length in bytes.
 * @param in Pointer to readable input bytes.
 * @param in_len Number of input bytes.
 * @return void
 */
void blake2b_hash(uint8_t *out, uint32_t out_len, const uint8_t *in,
                  size_t in_len);

/**
 * @brief Compute the Argon2 variable-length hash H' of a byte range.
 *
 * @param out Pointer to the hash output buffer.
 * @param out_len Requested output length in bytes.
 * @param in Pointer to readable input bytes.
 * @param in_len Number of input bytes.
 * @return void
 */
void blake2b_long(uint8_t *out, uint32_t out_len, const uint8_t *in,
                  size_t in_len);

#endif // BLAKE2B_H
