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
// File:    crypto_kdf.c
// Desc:    Implements the Argon2id passphrase key-derivation interface.
// Created: 2026

#include "crypto_kdf.h"

#include "argon2.h"

/**
 * @brief Populate the classroom Argon2id cost profile.
 *
 * @param p Pointer to the parameter block to fill.
 * @return void
 */
static void crypto_kdf_fill_profile(argon2_params_t *p) {
    p->time_cost = CRYPTO_KDF_TIME_COST;
    p->lanes = CRYPTO_KDF_PARALLELISM;
    p->memory_blocks = CRYPTO_KDF_MEMORY_BLOCKS;
    p->tag_len = CRYPTO_KDF_KEY_LEN;
    p->type = ARGON2_TYPE_ID;
}

/**
 * @brief Clear the optional Argon2 inputs for the classroom profile.
 *
 * @param p Pointer to the parameter block to clear.
 * @return void
 */
static void crypto_kdf_clear_extras(argon2_params_t *p) {
    p->secret = NULL;
    p->secret_len = 0u;
    p->ad = NULL;
    p->ad_len = 0u;
}

/**
 * @brief Validate the salt and password arguments.
 *
 * @param salt_len Number of salt bytes.
 * @param password Pointer to the passphrase bytes.
 * @param password_len Number of passphrase bytes.
 * @return bool true when the arguments are acceptable.
 */
static bool crypto_kdf_valid(size_t salt_len, const uint8_t *password,
                             size_t password_len) {
    if (salt_len < CRYPTO_KDF_SALT_MIN_LEN) {
        return false;
    }
    return (password != NULL) || (password_len == 0u);
}

bool crypto_kdf_argon2id(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint8_t key[CRYPTO_KDF_KEY_LEN]) {
    argon2_params_t params;
    if (!crypto_kdf_valid(salt_len, password, password_len)) {
        return false;
    }
    crypto_kdf_fill_profile(&params);
    crypto_kdf_clear_extras(&params);
    argon2_hash(&params, password, (uint32_t)password_len, salt,
                (uint32_t)salt_len, key);
    return true;
}
