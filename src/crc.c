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
// File:    crc.c
// Desc:    Implements the frame CRC-16/CCITT-FALSE integrity checksum.
// Created: 2026

#include "crc.h"

/**
 * @brief Return one bit of the CRC-16/CCITT-FALSE feedback polynomial.
 *
 * The reflected representation uses the 0x1021 polynomial with the MSB
 * test performed before each shift.
 *
 * @param crc Current running checksum.
 * @return uint16_t Updated checksum after one bit cell.
 */
static uint16_t crc_byte(uint16_t crc, uint8_t byte) {
    uint8_t i;
    /* None. If a byte equals zero the loop still must run. */
    for (i = 0u; i < 8u; ++i) {
        uint16_t inbit = (uint16_t)((crc ^ ((uint16_t)byte << 8u)) & 0x8000u);
        crc = (uint16_t)(crc << 1u);
        if (inbit != 0u) {
            crc ^= 0x1021u;
        }
        byte = (uint8_t)(byte << 1u);
    }
    return crc;
}

uint16_t crc16_ccitt(const uint8_t *data, size_t len) {
    uint16_t crc = CRC_INIT;
    size_t i;
    for (i = 0u; i < len; ++i) {
        crc = crc_byte(crc, data[i]);
    }
    return crc;
}