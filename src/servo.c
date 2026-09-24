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
// File:    servo.c
// Desc:    Implements the SG90 servo deadbolt PWM actuator.
// Created: 2026

#include "pico/stdlib.h"
#include "access_gate.h"
#include "servo.h"
#include "hardware/gpio.h"
#include "hardware/pwm.h"
#include <stdbool.h>
#include <stdint.h>

#ifndef GPIO_FUNC_PWM
/**
 * @brief GPIO function selector value for the PWM peripheral.
 */
#define GPIO_FUNC_PWM 4u
#endif

/**
 * @brief Clock divider applied to the servo PWM slice.
 */
#define SERVO_PWM_CLKDIV 64.0f

uint16_t servo_angle_to_pulse_us(uint8_t degrees) {
    uint32_t clamped = degrees;
    if (clamped > SERVO_MAX_ANGLE_DEGREES) {
        clamped = SERVO_MAX_ANGLE_DEGREES;
    }
    return (uint16_t)(SERVO_MIN_PULSE_US +
                      ((uint32_t)(SERVO_MAX_PULSE_US - SERVO_MIN_PULSE_US) *
                       clamped) / SERVO_MAX_ANGLE_DEGREES);
}

bool servo_init(void) {
    pwm_config cfg = pwm_get_default_config();
    pwm_config_set_clkdiv(&cfg, SERVO_PWM_CLKDIV);
    pwm_config_set_wrap(&cfg, (uint16_t)((125000000u / 50u) - 1u));
    pwm_init(pwm_gpio_to_slice_num(ACCESS_GATE_SERVO_PIN), &cfg, true);
    gpio_set_function(ACCESS_GATE_SERVO_PIN, GPIO_FUNC_PWM);
    servo_set_angle(SERVO_ANGLE_LOCKED_DEGREES);
    return true;
}

void servo_set_angle(uint8_t degrees) {
    pwm_set_gpio_level(ACCESS_GATE_SERVO_PIN,
                       servo_angle_to_pulse_us(degrees));
}

void servo_lock(void) {
    servo_set_angle(SERVO_ANGLE_LOCKED_DEGREES);
}

void servo_unlock(void) {
    servo_set_angle(SERVO_ANGLE_UNLOCKED_DEGREES);
}
