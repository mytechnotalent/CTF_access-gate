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
// File:    argon2.h
// Desc:    Declares the RFC 9106 Argon2id core parameters and entry point.
// Created: 2026

#ifndef ARGON2_H
#define ARGON2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Argon2 version implemented by this module (RFC 9106).
 */
#define ARGON2_VERSION 0x13u

/**
 * @brief Argon2i type identifier.
 */
#define ARGON2_TYPE_I 1u

/**
 * @brief Argon2id type identifier.
 */
#define ARGON2_TYPE_ID 2u

/**
 * @brief Size of one Argon2 memory block in bytes.
 */
#define ARGON2_BLOCK_LEN 1024u

/**
 * @brief Number of 64-bit words stored in one Argon2 memory block.
 */
#define ARGON2_WORDS_IN_BLOCK 128u

/**
 * @brief Number of vertical slices a pass is partitioned into.
 */
#define ARGON2_SYNC_POINTS 4u

/**
 * @brief Number of pseudo-random addresses produced by one address block.
 */
#define ARGON2_ADDRESSES_IN_BLOCK 128u

/**
 * @brief Argon2 cost profile and optional inputs.
 */
typedef struct argon2_params {
    /**
     * @brief Number of passes over the memory.
     */
    uint32_t time_cost;
    /**
     * @brief Number of parallel lanes.
     */
    uint32_t lanes;
    /**
     * @brief Requested memory in 1 KiB blocks.
     */
    uint32_t memory_blocks;
    /**
     * @brief Tag length in bytes.
     */
    uint32_t tag_len;
    /**
     * @brief Argon2 type identifier.
     */
    uint32_t type;
    /**
     * @brief Pointer to the optional secret key bytes.
     */
    const uint8_t *secret;
    /**
     * @brief Number of secret key bytes.
     */
    uint32_t secret_len;
    /**
     * @brief Pointer to the optional associated data bytes.
     */
    const uint8_t *ad;
    /**
     * @brief Number of associated data bytes.
     */
    uint32_t ad_len;
} argon2_params_t;

/**
 * @brief Run the Argon2 core over the given parameters.
 *
 * @param params Pointer to the cost profile and optional inputs.
 * @param password Pointer to the password bytes.
 * @param password_len Number of password bytes.
 * @param salt Pointer to the salt bytes.
 * @param salt_len Number of salt bytes.
 * @param out Pointer to the tag output buffer.
 * @return void
 */
void argon2_hash(const argon2_params_t *params, const uint8_t *password,
                 uint32_t password_len, const uint8_t *salt,
                 uint32_t salt_len, uint8_t *out);

#endif // ARGON2_H
