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
// File:    field_secrets.h
// Desc:    LAB-ONLY shared field passphrase and salt matching the Python
//          instructor gateway for the COLD IRON authenticated telemetry lab.
// Created: 2026

#ifndef FIELD_SECRETS_H
#define FIELD_SECRETS_H

#include <stdint.h>

/**
 * @brief LAB-ONLY shared field passphrase.
 *
 * WARNING: This value is committed for the classroom lab so the firmware
 * and the instructor gateway derive the same session key. Production
 * firmware MUST provision the session key from one-time-programmable
 * (OTP) memory at manufacture and MUST NEVER embed a passphrase or a
 * derived key in flash. Shipping this file as-is is a lab convenience,
 * not a secure deployment.
 */
#define FIELD_SECRET_PASSPHRASE "operation cold iron field key v1"

/**
 * @brief LAB-ONLY Argon2id salt, the ASCII bytes "coldiron-salt-01".
 *
 * WARNING: As with the passphrase, this salt is a lab convenience. A real
 * deployment derives or provisions unique per-device key material through
 * OTP and never relies on a shared committed salt.
 */
static const uint8_t FIELD_SECRET_SALT[16] = { 0x63,0x6f,0x6c,0x64,0x69,0x72,0x6f,0x6e,0x2d,0x73,0x61,0x6c,0x74,0x2d,0x30,0x31 };

#endif // FIELD_SECRETS_H
