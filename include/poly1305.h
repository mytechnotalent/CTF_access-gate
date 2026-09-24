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
// File:    poly1305.h
// Desc:    Declares the Poly1305 one-time message authenticator.
// Created: 2026

#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Poly1305 one-time key size in bytes.
 */
#define POLY1305_KEY_LEN 32u

/**
 * @brief Poly1305 authentication tag size in bytes.
 */
#define POLY1305_TAG_LEN 16u

/**
 * @brief Compute a Poly1305 tag over a message.
 *
 * @param key Pointer to a 32-byte one-time key.
 * @param msg Pointer to the message bytes.
 * @param len Number of message bytes.
 * @param tag Pointer to a 16-byte tag output buffer.
 * @return void
 */
void poly1305_mac(const uint8_t key[POLY1305_KEY_LEN], const uint8_t *msg,
                  size_t len, uint8_t tag[POLY1305_TAG_LEN]);

#endif // POLY1305_H
