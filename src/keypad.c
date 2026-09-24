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
// File:    keypad.c
// Desc:    Implements the NEC keypad PIN accumulator with a bounded
//          digit count and a ready-before-consume guard.
// Created: 2026

#include "keypad.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Digits currently held by the accumulator.
 */
static uint8_t g_keypad_digits[KEYPAD_MAX_DIGITS];

/**
 * @brief Number of digits currently held by the accumulator.
 */
static uint8_t g_keypad_count;

/**
 * @brief True when a full-length PIN has been latched by ENTER.
 */
static bool g_keypad_entered;

void keypad_reset(void) {
    memset(g_keypad_digits, 0, sizeof(g_keypad_digits));
    g_keypad_count = 0u;
    g_keypad_entered = false;
}

bool keypad_push_digit(uint8_t digit) {
    if (digit > 9u || g_keypad_count >= ACCESS_GATE_PIN_LENGTH) {
        return false;
    }
    g_keypad_digits[g_keypad_count] = digit;
    g_keypad_count = (uint8_t)(g_keypad_count + 1u);
    g_keypad_entered = false;
    return true;
}

void keypad_clear(void) {
    g_keypad_count = 0u;
    g_keypad_entered = false;
}

bool keypad_enter(void) {
    if (g_keypad_count != ACCESS_GATE_PIN_LENGTH) {
        return false;
    }
    g_keypad_entered = true;
    return true;
}

bool keypad_pin_ready(void) {
    return g_keypad_entered && g_keypad_count == ACCESS_GATE_PIN_LENGTH;
}

bool keypad_get_pin(char *out, size_t out_len) {
    uint8_t i;
    if (!keypad_pin_ready() || out == NULL || out_len <= ACCESS_GATE_PIN_LENGTH) {
        return false;
    }
    for (i = 0u; i < g_keypad_count; ++i) {
        out[i] = (char)('0' + g_keypad_digits[i]);
    }
    out[g_keypad_count] = '\0';
    keypad_clear();
    return true;
}
