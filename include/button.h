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
// File:    button.h
// Desc:    Declares the debounced request-to-exit (REX) push-button input.
// Created: 2026

#ifndef BUTTON_H
#define BUTTON_H

#include "access_gate.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Contact bounce lockout window in microseconds.
 */
#define REX_DEBOUNCE_US 30000u

/**
 * @brief Initialize the request-to-exit push-button input.
 *
 * Configures the button GPIO as an input with the internal pull-up
 * enabled, because the switch shorts the pin to ground when pressed.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool rex_init(void);

/**
 * @brief Report whether the request-to-exit button is held down.
 *
 * @param void No parameters.
 * @return bool true while the pin reads low (pressed).
 */
bool rex_pressed(void);

/**
 * @brief Consume one debounced request-to-exit press edge.
 *
 * This egress path is deliberately unauthenticated for life safety: a
 * person inside the vault must always be able to leave without a badge,
 * a PIN, or a desk grant. The project discusses that trade-off rather
 * than closing it, because a fail-secure egress is a fire hazard.
 *
 * @param void No parameters.
 * @return bool true when a new press edge was consumed.
 */
bool rex_consume_press(void);

/**
 * @brief Clear the debounce state.
 *
 * @param void No parameters.
 * @return void
 */
void rex_reset(void);

#endif // BUTTON_H
