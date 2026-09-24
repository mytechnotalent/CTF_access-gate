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
// File:    envelope.h
// Desc:    Declares the hex XChaCha20-Poly1305 telemetry envelope codec.
// Created: 2026

#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Extended nonce size in bytes on the wire.
 */
#define ENVELOPE_NONCE_LEN 24u

/**
 * @brief Authentication tag size in bytes on the wire.
 */
#define ENVELOPE_TAG_LEN 16u

/**
 * @brief Maximum plaintext body accepted by the envelope codec.
 */
#define ENVELOPE_MAX_PLAINTEXT 48u

/**
 * @brief Maximum NUL-terminated lowercase hex envelope length in bytes.
 *
 * The wire form is the lowercase hex of nonce || ciphertext || tag.
 */
#define ENVELOPE_MAX_HEX_LEN ((ENVELOPE_NONCE_LEN + ENVELOPE_MAX_PLAINTEXT + ENVELOPE_TAG_LEN) * 2u + 1u)

/**
 * @brief Fill a 24-byte nonce from the RP2350 hardware random source.
 *
 * @param nonce Pointer to a 24-byte nonce output buffer.
 * @return void
 */
void envelope_fill_nonce(uint8_t nonce[ENVELOPE_NONCE_LEN]);

/**
 * @brief Seal a plaintext body into a lowercase hex envelope.
 *
 * Writes the lowercase hex of nonce || ciphertext || tag with a trailing
 * NUL. Fails when the plaintext exceeds ENVELOPE_MAX_PLAINTEXT or the
 * output buffer cannot hold the full hex string.
 *
 * @param key Pointer to a 32-byte session key.
 * @param nonce Pointer to the 24-byte unique nonce.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param pt Pointer to the plaintext bytes.
 * @param pt_len Number of plaintext bytes.
 * @param out Pointer to the NUL-terminated hex output buffer.
 * @param out_len Capacity of the hex output buffer in bytes.
 * @return bool true when the envelope was sealed and encoded.
 */
bool envelope_seal_hex(const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t ad_len, const uint8_t *pt, size_t pt_len, char *out, size_t out_len);

/**
 * @brief Open and authenticate a lowercase or uppercase hex envelope.
 *
 * Decodes an even-length hex string, requires at least a nonce and tag,
 * verifies the tag, and copies the recovered plaintext. Any malformed,
 * tampered, or forged input yields false and no trusted plaintext.
 *
 * @param key Pointer to a 32-byte session key.
 * @param ad Pointer to associated data authenticated but not encrypted.
 * @param ad_len Number of associated-data bytes.
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param pt_out Pointer to the plaintext output buffer.
 * @param pt_out_len Capacity of the plaintext output buffer in bytes.
 * @param pt_len Pointer to store the recovered plaintext length.
 * @return bool true when the tag verified and plaintext was produced.
 */
bool envelope_open_hex(const uint8_t key[32], const uint8_t *ad, size_t ad_len, const char *hex, uint8_t *pt_out, size_t pt_out_len, size_t *pt_len);

#endif // ENVELOPE_H
