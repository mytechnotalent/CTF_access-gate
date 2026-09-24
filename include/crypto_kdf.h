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
// File:    crypto_kdf.h
// Desc:    Declares the Argon2id passphrase key-derivation interface.
// Created: 2026

#ifndef CRYPTO_KDF_H
#define CRYPTO_KDF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Derived key length in bytes.
 */
#define CRYPTO_KDF_KEY_LEN 32u

/**
 * @brief Minimum accepted salt length in bytes.
 */
#define CRYPTO_KDF_SALT_MIN_LEN 8u

/**
 * @brief Argon2id pass count used by the classroom profile.
 */
#define CRYPTO_KDF_TIME_COST 3u

/**
 * @brief Argon2id lane count used by the classroom profile.
 */
#define CRYPTO_KDF_PARALLELISM 1u

/**
 * @brief Argon2id memory block count used by the classroom profile.
 */
#define CRYPTO_KDF_MEMORY_BLOCKS 64u

/**
 * @brief Derive a 32-byte key from a passphrase with Argon2id.
 *
 * Runs the Argon2id hybrid construction over the password and salt with
 * the classroom cost profile and writes the derived key. The profile is
 * tuned for the RP2350 SRAM budget in the field chapter and is expected
 * to be raised on a host gateway.
 *
 * @param password Pointer to the passphrase bytes.
 * @param password_len Number of passphrase bytes.
 * @param salt Pointer to the salt bytes.
 * @param salt_len Number of salt bytes (at least CRYPTO_KDF_SALT_MIN_LEN).
 * @param key Pointer to a 32-byte derived-key output buffer.
 * @return bool true when the key was derived.
 */
bool crypto_kdf_argon2id(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint8_t key[CRYPTO_KDF_KEY_LEN]);

#endif // CRYPTO_KDF_H
