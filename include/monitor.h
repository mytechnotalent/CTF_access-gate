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
// File:    monitor.h
// Desc:    Declares the access-gate state machine tying the keypad, auth,
//          deadbolt, interlock, radio, and access log together.
// Created: 2026

#ifndef MONITOR_H
#define MONITOR_H

#include "crypto_aead.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Bounded deadbolt release hold in milliseconds.
 */
#define MONITOR_HOLD_MS 5000u

/**
 * @brief Number of monitor ticks between onboard heartbeat toggles.
 */
#define MONITOR_HEARTBEAT_TICKS 4u

/**
 * @brief Length in bytes of a desk grant reply body.
 *
 * The body is a little-endian 32-bit sequence followed by a 16-byte
 * authenticated state tag.
 */
#define MONITOR_REPLY_LEN (4u + CRYPTO_AEAD_TAG_LEN)

/**
 * @brief Infrared command code for the digit zero key.
 */
#define MONITOR_IR_DIGIT_0 0x16u

/**
 * @brief Infrared command code for the digit one key.
 */
#define MONITOR_IR_DIGIT_1 0x0Cu

/**
 * @brief Infrared command code for the digit two key.
 */
#define MONITOR_IR_DIGIT_2 0x18u

/**
 * @brief Infrared command code for the digit three key.
 */
#define MONITOR_IR_DIGIT_3 0x5Eu

/**
 * @brief Infrared command code for the digit four key.
 */
#define MONITOR_IR_DIGIT_4 0x08u

/**
 * @brief Infrared command code for the digit five key.
 */
#define MONITOR_IR_DIGIT_5 0x1Cu

/**
 * @brief Infrared command code for the digit six key.
 */
#define MONITOR_IR_DIGIT_6 0x5Au

/**
 * @brief Infrared command code for the digit seven key.
 */
#define MONITOR_IR_DIGIT_7 0x42u

/**
 * @brief Infrared command code for the digit eight key.
 */
#define MONITOR_IR_DIGIT_8 0x52u

/**
 * @brief Infrared command code for the digit nine key.
 */
#define MONITOR_IR_DIGIT_9 0x4Au

/**
 * @brief Infrared command code for the ENTER key.
 */
#define MONITOR_IR_ENTER_COMMAND 0x46u

/**
 * @brief Infrared command code for the CLEAR key.
 */
#define MONITOR_IR_CLEAR_COMMAND 0x45u

/**
 * @brief Initialize the access-gate state machine.
 *
 * Configures the I2C LCD, the DHT11 interlock, the infrared keypad, the
 * annunciator LEDs, the deadbolt servo, the request-to-exit button, the
 * RYLR998 radio, and derives the Argon2id field key.
 *
 * @param void No parameters.
 * @return bool true when all submodules initialized.
 */
bool monitor_init(void);

/**
 * @brief Clear the gate-ready flag.
 *
 * Test and recovery hook that returns the state machine to the
 * uninitialized policy state.
 *
 * @param void No parameters.
 * @return void
 */
void monitor_deinit(void);

/**
 * @brief Execute one access-gate state-machine tick.
 *
 * Samples the interlock, services the keypad, radio, and request-to-exit
 * inputs, expires the pending and hold timers, and renders the access log.
 *
 * @param void No parameters.
 * @return bool true when the tick completed without a policy error.
 */
bool monitor_step(void);

#endif // MONITOR_H
