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
// File:    chacha20.h
// Desc:    Declares the ChaCha20 stream cipher and HChaCha20 subkey function.
// Created: 2026

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief ChaCha20 key size in bytes.
 */
#define CHACHA20_KEY_LEN 32u

/**
 * @brief ChaCha20 IETF nonce size in bytes.
 */
#define CHACHA20_NONCE_LEN 12u

/**
 * @brief HChaCha20 extended nonce size in bytes.
 */
#define CHACHA20_HNONCE_LEN 16u

/**
 * @brief ChaCha20 block size in bytes.
 */
#define CHACHA20_BLOCK_LEN 64u

/**
 * @brief Generate one ChaCha20 keystream block.
 *
 * @param key Pointer to a 32-byte key.
 * @param counter Block counter to place in the state.
 * @param nonce Pointer to the 12-byte IETF nonce.
 * @param out Pointer to a 64-byte keystream output buffer.
 * @return void
 */
void chacha20_block(const uint8_t key[CHACHA20_KEY_LEN], uint32_t counter,
                    const uint8_t nonce[CHACHA20_NONCE_LEN],
                    uint8_t out[CHACHA20_BLOCK_LEN]);

/**
 * @brief Encrypt or decrypt a byte range with the ChaCha20 stream.
 *
 * @param key Pointer to a 32-byte key.
 * @param nonce Pointer to the 12-byte IETF nonce.
 * @param counter Initial block counter.
 * @param in Pointer to the input bytes.
 * @param out Pointer to the output bytes (may alias in).
 * @param len Number of bytes to process.
 * @return void
 */
void chacha20_xor(const uint8_t key[CHACHA20_KEY_LEN],
                  const uint8_t nonce[CHACHA20_NONCE_LEN], uint32_t counter,
                  const uint8_t *in, uint8_t *out, size_t len);

/**
 * @brief Derive a 32-byte subkey from a 16-byte extended nonce.
 *
 * @param key Pointer to a 32-byte key.
 * @param nonce Pointer to the 16-byte extended nonce.
 * @param out Pointer to a 32-byte subkey output buffer.
 * @return void
 */
void hchacha20(const uint8_t key[CHACHA20_KEY_LEN],
               const uint8_t nonce[CHACHA20_HNONCE_LEN],
               uint8_t out[CHACHA20_KEY_LEN]);

#endif // CHACHA20_H
