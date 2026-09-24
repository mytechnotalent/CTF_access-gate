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
// File:    crypto_aead.h
// Desc:    Declares the XChaCha20-Poly1305 authenticated telemetry envelope.
// Created: 2026

#ifndef CRYPTO_AEAD_H
#define CRYPTO_AEAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Symmetric session key size in bytes.
 */
#define CRYPTO_AEAD_KEY_LEN 32u

/**
 * @brief Extended nonce size in bytes (XChaCha20).
 */
#define CRYPTO_AEAD_NONCE_LEN 24u

/**
 * @brief Authentication tag size in bytes.
 */
#define CRYPTO_AEAD_TAG_LEN 16u

/**
 * @brief Overhead in bytes added by the envelope beyond the payload.
 */
#define CRYPTO_AEAD_OVERHEAD (CRYPTO_AEAD_NONCE_LEN + CRYPTO_AEAD_TAG_LEN)

/**
 * @brief Seal a plaintext frame with XChaCha20-Poly1305.
 *
 * Derives a subkey from the 24-byte nonce with HChaCha20, encrypts the
 * plaintext, and authenticates the associated data and ciphertext. The
 * caller-provided nonce must be unpredictable for every frame.
 *
 * @param key Pointer to a 32-byte session key.
 * @param nonce Pointer to a 24-byte unique nonce.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param pt Pointer to the plaintext bytes.
 * @param pt_len Number of plaintext bytes.
 * @param ct Pointer to the ciphertext output buffer.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return bool true when the frame was sealed.
 */
bool crypto_aead_seal(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                      const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                      const uint8_t *ad, size_t ad_len, const uint8_t *pt,
                      size_t pt_len, uint8_t *ct,
                      uint8_t tag[CRYPTO_AEAD_TAG_LEN]);

/**
 * @brief Open and authenticate an XChaCha20-Poly1305 frame.
 *
 * Recomputes the tag over the associated data and ciphertext and only
 * decrypts when it matches in constant time. A tampered or forged frame
 * therefore never yields plaintext.
 *
 * @param key Pointer to a 32-byte session key.
 * @param nonce Pointer to the 24-byte nonce used to seal.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param ct Pointer to the ciphertext bytes.
 * @param ct_len Number of ciphertext bytes.
 * @param tag Pointer to the 16-byte tag to verify.
 * @param pt Pointer to the plaintext output buffer.
 * @return bool true when the tag verified and plaintext was produced.
 */
bool crypto_aead_open(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                      const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                      const uint8_t *ad, size_t ad_len, const uint8_t *ct,
                      size_t ct_len, const uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                      uint8_t *pt);

/**
 * @brief Compare two tags in constant time.
 *
 * @param left Pointer to the first tag.
 * @param right Pointer to the second tag.
 * @return bool true when the tags are equal.
 */
bool crypto_aead_tag_equal(const uint8_t left[CRYPTO_AEAD_TAG_LEN],
                           const uint8_t right[CRYPTO_AEAD_TAG_LEN]);

#endif // CRYPTO_AEAD_H
