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
// File:    status_led.c
// Desc:    Implements the red, yellow, and green access-gate state annunciator.
// Created: 2026

#include "pico/stdlib.h"
#include "access_gate.h"
#include "status_led.h"
#include "hardware/gpio.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Configure one annunciator GPIO as a dark output.
 *
 * @param pin GPIO pin number to configure.
 * @return void
 */
static void status_led_config_pin(uint pin) {
    gpio_init(pin);
    gpio_set_dir(pin, GPIO_OUT);
    gpio_put(pin, 0);
}

bool status_led_init(void) {
    status_led_config_pin(ACCESS_GATE_RED_LED_PIN);
    status_led_config_pin(ACCESS_GATE_YELLOW_LED_PIN);
    status_led_config_pin(ACCESS_GATE_GREEN_LED_PIN);
    return true;
}

void status_led_show(status_led_state_t state) {
    gpio_put(ACCESS_GATE_RED_LED_PIN, state == STATUS_LED_DENIED);
    gpio_put(ACCESS_GATE_YELLOW_LED_PIN, state == STATUS_LED_PENDING);
    gpio_put(ACCESS_GATE_GREEN_LED_PIN, state == STATUS_LED_GRANTED);
}
