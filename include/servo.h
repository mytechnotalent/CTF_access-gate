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
// File:    servo.h
// Desc:    Declares the SG90 servo deadbolt PWM actuator.
// Created: 2026

#ifndef SERVO_H
#define SERVO_H

#include "access_gate.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Pulse width in microseconds for a zero degree servo command.
 */
#define SERVO_MIN_PULSE_US 500u

/**
 * @brief Pulse width in microseconds for a 180 degree servo command.
 */
#define SERVO_MAX_PULSE_US 2500u

/**
 * @brief Servo control period in microseconds (50 Hz).
 */
#define SERVO_PERIOD_US 20000u

/**
 * @brief Full-scale servo angle in degrees.
 */
#define SERVO_MAX_ANGLE_DEGREES 180u

/**
 * @brief Deadbolt angle that fully seals the door.
 */
#define SERVO_ANGLE_LOCKED_DEGREES 0u

/**
 * @brief Deadbolt angle that fully opens the door.
 */
#define SERVO_ANGLE_UNLOCKED_DEGREES 90u

/**
 * @brief Initialize the deadbolt servo PWM output.
 *
 * Configures the servo GPIO for PWM at 50 Hz and drives the deadbolt to
 * the locked position.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool servo_init(void);

/**
 * @brief Convert an angle to a servo pulse width.
 *
 * Pure mapping used by the driver and the native tests. Values above
 * SERVO_MAX_ANGLE_DEGREES clamp to the maximum pulse width.
 *
 * @param degrees Requested deadbolt angle in degrees.
 * @return uint16_t Pulse width in microseconds.
 */
uint16_t servo_angle_to_pulse_us(uint8_t degrees);

/**
 * @brief Command the deadbolt servo to an angle.
 *
 * @param degrees Requested deadbolt angle in degrees.
 * @return void
 */
void servo_set_angle(uint8_t degrees);

/**
 * @brief Seal the deadbolt (zero degrees).
 *
 * @param void No parameters.
 * @return void
 */
void servo_lock(void);

/**
 * @brief Open the deadbolt (ninety degrees).
 *
 * @param void No parameters.
 * @return void
 */
void servo_unlock(void);

#endif // SERVO_H
