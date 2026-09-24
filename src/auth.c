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
// File:    auth.c
// Desc:    Implements the authorization record, the monotonic anti-replay
//          window, and the keyed state tag that guards the SRAM verdict.
// Created: 2026

#include "auth.h"
#include "crypto_aead.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Field key used to compute and verify state tags.
 */
static uint8_t g_auth_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once a field key has been installed.
 */
static bool g_auth_key_ready;

/**
 * @brief Write one 32-bit value in little-endian order.
 *
 * @param out Pointer to the four-byte output.
 * @param value Value to serialize.
 * @return void
 */
static void auth_put_u32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8u) & 0xFFu);
    out[2] = (uint8_t)((value >> 16u) & 0xFFu);
    out[3] = (uint8_t)((value >> 24u) & 0xFFu);
}

/**
 * @brief Serialize the authenticated fields of a record.
 *
 * @param auth Pointer to the authorization record.
 * @param rec Pointer to the AUTH_RECORD_LEN output buffer.
 * @return void
 */
static void auth_serialize(const gate_auth_t *auth, uint8_t rec[AUTH_RECORD_LEN]) {
    rec[0] = auth->granted ? 1u : 0u;
    rec[1] = auth->pending ? 1u : 0u;
    auth_put_u32(&rec[2], auth->seq);
    auth_put_u32(&rec[6], auth->last_seq);
}

/**
 * @brief Build the deterministic state-tag nonce for a sequence number.
 *
 * @param seq Sequence number bound into the nonce.
 * @param nonce Pointer to the 24-byte nonce output buffer.
 * @return void
 */
static void auth_nonce(uint32_t seq, uint8_t nonce[CRYPTO_AEAD_NONCE_LEN]) {
    memset(nonce, 0, CRYPTO_AEAD_NONCE_LEN);
    auth_put_u32(nonce, seq);
    nonce[4] = AUTH_NONCE_DOMAIN;
}

void auth_init(gate_auth_t *auth) {
    if (auth == NULL) {
        return;
    }
    memset(auth, 0, sizeof(*auth));
}

void auth_set_key(const uint8_t key[CRYPTO_AEAD_KEY_LEN]) {
    if (key == NULL) {
        g_auth_key_ready = false;
        return;
    }
    memcpy(g_auth_key, key, CRYPTO_AEAD_KEY_LEN);
    g_auth_key_ready = true;
}

void auth_begin_request(gate_auth_t *auth) {
    if (auth == NULL) {
        return;
    }
    auth->pending = true;
    auth->granted = false;
    auth->seq = 0u;
    memset(auth->tag, 0, sizeof(auth->tag));
}

bool auth_state_tag(const gate_auth_t *auth,
                    uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    uint8_t record[AUTH_RECORD_LEN];
    uint8_t nonce[CRYPTO_AEAD_NONCE_LEN];
    uint8_t ct[AUTH_RECORD_LEN];
    if (!g_auth_key_ready || auth == NULL || tag == NULL) {
        return false;
    }
    auth_serialize(auth, record);
    auth_nonce(auth->seq, nonce);
    return crypto_aead_seal(g_auth_key, nonce, record, sizeof(record), record, 0u, ct, tag);
}

bool auth_state_ok(const gate_auth_t *auth) {
    uint8_t expect[CRYPTO_AEAD_TAG_LEN];
    if (auth == NULL || !auth_state_tag(auth, expect)) {
        return false;
    }
    return crypto_aead_tag_equal(expect, auth->tag);
}

/**
 * @brief Build the record that a grant for a sequence would produce.
 *
 * @param seq Sequence number carried by the grant.
 * @param candidate Pointer to the candidate authorization record.
 * @return void
 */
static void auth_candidate(uint32_t seq, gate_auth_t *candidate) {
    auth_init(candidate);
    candidate->granted = true;
    candidate->seq = seq;
    candidate->last_seq = seq;
}

/**
 * @brief Report whether a grant tag matches the record it would produce.
 *
 * @param seq Sequence number carried by the grant.
 * @param tag Pointer to the 16-byte grant tag to verify.
 * @return bool true when the tag matches the candidate record.
 */
static bool auth_tag_matches(uint32_t seq,
                             const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    gate_auth_t candidate;
    uint8_t expect[CRYPTO_AEAD_TAG_LEN];
    auth_candidate(seq, &candidate);
    if (!auth_state_tag(&candidate, expect)) {
        return false;
    }
    return crypto_aead_tag_equal(expect, tag);
}

/**
 * @brief Write an accepted grant into the authorization record.
 *
 * @param auth Pointer to the authorization record.
 * @param seq Sequence number carried by the grant.
 * @param tag Pointer to the verified 16-byte grant tag.
 * @return void
 */
static void auth_accept(gate_auth_t *auth, uint32_t seq,
                        const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    auth->granted = true;
    auth->pending = false;
    auth->seq = seq;
    auth->last_seq = seq;
    memcpy(auth->tag, tag, CRYPTO_AEAD_TAG_LEN);
}

bool auth_apply_grant(gate_auth_t *auth, uint32_t seq,
                      const uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    if (auth == NULL || tag == NULL) {
        return false;
    }
    if (seq <= auth->last_seq) {
        return false;
    }
    if (!auth_tag_matches(seq, tag)) {
        return false;
    }
    auth_accept(auth, seq, tag);
    return true;
}
