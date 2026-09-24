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
// File:    keypad.h
// Desc:    Declares the NEC keypad PIN accumulator.
// Created: 2026

#ifndef KEYPAD_H
#define KEYPAD_H

#include "access_gate.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Maximum number of digits the accumulator can hold.
 */
#define KEYPAD_MAX_DIGITS ACCESS_GATE_PIN_LENGTH

/**
 * @brief Clear the accumulator and the entered latch.
 *
 * @param void No parameters.
 * @return void
 */
void keypad_reset(void);

/**
 * @brief Push one decimal digit onto the accumulator.
 *
 * Rejects any value above nine and any digit that would overflow the
 * bounded PIN length.
 *
 * @param digit Decimal digit value zero through nine.
 * @return bool true when the digit was accepted.
 */
bool keypad_push_digit(uint8_t digit);

/**
 * @brief Discard every digit held by the accumulator.
 *
 * @param void No parameters.
 * @return void
 */
void keypad_clear(void);

/**
 * @brief Latch the PIN as ready for consumption.
 *
 * Only a full-length PIN can be latched. Once latched the PIN must be
 * consumed before another can be entered.
 *
 * @param void No parameters.
 * @return bool true when a full-length PIN was latched.
 */
bool keypad_enter(void);

/**
 * @brief Report whether a full-length PIN is latched and ready.
 *
 * @param void No parameters.
 * @return bool true when exactly ACCESS_GATE_PIN_LENGTH digits are held.
 */
bool keypad_pin_ready(void);

/**
 * @brief Copy out and consume the latched PIN.
 *
 * Enforces the ready-before-consume guard: it fails unless a full-length
 * PIN was latched, and it clears the accumulator so the same PIN cannot
 * be consumed twice.
 *
 * @param out Pointer to the NUL-terminated PIN output buffer.
 * @param out_len Capacity of the output buffer in bytes.
 * @return bool true when the PIN was copied and consumed.
 */
bool keypad_get_pin(char *out, size_t out_len);

#endif // KEYPAD_H
