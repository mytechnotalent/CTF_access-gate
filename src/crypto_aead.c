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
// File:    crypto_aead.c
// Desc:    Implements the XChaCha20-Poly1305 authenticated telemetry
//          envelope with constant-time tag verification.
// Created: 2026

#include "crypto_aead.h"
#include "chacha20.h"
#include "poly1305.h"

/**
 * @brief Compute the AEAD tag over associated data and ciphertext.
 *
 * @param key Pointer to a 32-byte one-time key.
 * @param ad Pointer to the associated-data bytes.
 * @param ad_len Number of associated-data bytes.
 * @param ct Pointer to the ciphertext bytes.
 * @param ct_len Number of ciphertext bytes.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return void
 */
void poly1305_mac_aead(const uint8_t key[POLY1305_KEY_LEN], const uint8_t *ad, size_t ad_len,
                       const uint8_t *ct, size_t ct_len, uint8_t tag[POLY1305_TAG_LEN]);

/**
 * @brief Build the 12-byte IETF nonce from the last 8 extended nonce bytes.
 *
 * @param nonce Pointer to the 24-byte extended nonce.
 * @param ietf Pointer to the 12-byte IETF nonce output.
 * @return void
 */
static void crypto_aead_set_ietf(const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                                 uint8_t ietf[CHACHA20_NONCE_LEN]) {
    uint8_t i;
    for (i = 0u; i < 4u; ++i) { ietf[i] = 0u; }
    for (i = 4u; i < CHACHA20_NONCE_LEN; ++i) { ietf[i] = nonce[i + 12u]; }
}

/**
 * @brief Derive the session subkey and the Poly1305 one-time key.
 *
 * @param key Pointer to a 32-byte session key.
 * @param nonce Pointer to the 24-byte extended nonce.
 * @param subkey Pointer to a 32-byte subkey output buffer.
 * @param otk Pointer to a 64-byte one-time key block output.
 * @return void
 */
static void crypto_aead_derive(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                               const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN],
                               uint8_t subkey[CRYPTO_AEAD_KEY_LEN], uint8_t otk[CHACHA20_BLOCK_LEN]) {
    uint8_t ietf[CHACHA20_NONCE_LEN];
    crypto_aead_set_ietf(nonce, ietf);
    hchacha20(key, nonce, subkey);
    chacha20_block(subkey, 0u, ietf, otk);
}

/**
 * @brief Encrypt or decrypt with the subkey starting at block counter one.
 *
 * @param subkey Pointer to the 32-byte derived subkey.
 * @param nonce Pointer to the 24-byte extended nonce.
 * @param in Pointer to the input bytes.
 * @param out Pointer to the output bytes (may alias in).
 * @param len Number of bytes to process.
 * @return void
 */
static void crypto_aead_crypt(const uint8_t subkey[CRYPTO_AEAD_KEY_LEN],
                              const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN], const uint8_t *in,
                              uint8_t *out, size_t len) {
    uint8_t ietf[CHACHA20_NONCE_LEN];
    crypto_aead_set_ietf(nonce, ietf);
    chacha20_xor(subkey, ietf, 1u, in, out, len);
}

bool crypto_aead_tag_equal(const uint8_t left[CRYPTO_AEAD_TAG_LEN],
                           const uint8_t right[CRYPTO_AEAD_TAG_LEN]) {
    uint8_t diff = 0u;
    uint8_t i;
    for (i = 0u; i < CRYPTO_AEAD_TAG_LEN; ++i) { diff |= (uint8_t)(left[i] ^ right[i]); }
    return diff == 0u;
}

bool crypto_aead_seal(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                      const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN], const uint8_t *ad, size_t ad_len,
                      const uint8_t *pt, size_t pt_len, uint8_t *ct,
                      uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    uint8_t subkey[CRYPTO_AEAD_KEY_LEN];
    uint8_t otk[CHACHA20_BLOCK_LEN];
    crypto_aead_derive(key, nonce, subkey, otk);
    crypto_aead_crypt(subkey, nonce, pt, ct, pt_len);
    poly1305_mac_aead(otk, ad, ad_len, ct, pt_len, tag);
    return true;
}

bool crypto_aead_open(const uint8_t key[CRYPTO_AEAD_KEY_LEN],
                      const uint8_t nonce[CRYPTO_AEAD_NONCE_LEN], const uint8_t *ad, size_t ad_len,
                      const uint8_t *ct, size_t ct_len, const uint8_t tag[CRYPTO_AEAD_TAG_LEN],
                      uint8_t *pt) {
    uint8_t subkey[CRYPTO_AEAD_KEY_LEN];
    uint8_t otk[CHACHA20_BLOCK_LEN];
    uint8_t expect[CRYPTO_AEAD_TAG_LEN];
    crypto_aead_derive(key, nonce, subkey, otk);
    poly1305_mac_aead(otk, ad, ad_len, ct, ct_len, expect);
    if (!crypto_aead_tag_equal(expect, tag)) { return false; }
    crypto_aead_crypt(subkey, nonce, ct, pt, ct_len);
    return true;
}
