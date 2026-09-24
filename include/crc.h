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
// File:    crc.h
// Desc:    Declares the frame CRC-16/CCITT integrity primitive.
// Created: 2026

#ifndef CRC_H
#define CRC_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief CRC-16/CCITT seed value used for telemetry frame integrity.
 *
 * The running checksum starts from this value and is never reset by the
 * transport. Integrity only, never authenticity.
 */
#define CRC_INIT 0xFFFFu

/**
 * @brief Compute the CRC-16/CCITT-FALSE checksum of a byte buffer.
 *
 * @param data Pointer to readable bytes.
 * @param len Number of bytes to checksum.
 * @return uint16_t Computed CRC-16 residual value.
 */
uint16_t crc16_ccitt(const uint8_t *data, size_t len);

#endif // CRC_H