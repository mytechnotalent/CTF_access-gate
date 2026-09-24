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
// File:    access_gate.h
// Desc:    Declares platform pin mapping, peripheral handles, and
//          provisioning boundaries for the Access Gate firmware.
// Created: 2026

#ifndef ACCESS_GATE_H
#define ACCESS_GATE_H

#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "packet_artifact.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Onboard green LED GPIO pin number.
 *
 * The RP2350 Pico 2 onboard LED is connected to GPIO 25. It is blinked
 * rapidly whenever the edge device completes a successful LoRa transmit.
 */
#define ACCESS_GATE_LED_PIN 25u

/**
 * @brief DHT11 one-wire data GPIO pin number.
 *
 * The DHT11 single data line is the vault environmental interlock.
 */
#define ACCESS_GATE_DHT_PIN 4u

/**
 * @brief I2C peripheral used by the 1602 LCD backpack.
 *
 * The Pico 2 bus B (I2C1) drives the PCF8574 backpack on the display.
 */
#define ACCESS_GATE_I2C i2c1

/**
 * @brief I2C SDA GPIO pin number.
 */
#define ACCESS_GATE_I2C_SDA 2u

/**
 * @brief I2C SCL GPIO pin number.
 */
#define ACCESS_GATE_I2C_SCL 3u

/**
 * @brief I2C bus clock rate in hertz.
 */
#define ACCESS_GATE_I2C_BAUD 100000u

/**
 * @brief I2C address of the 1602 LCD PCF8574 backpack.
 *
 * The most common PCF8574 backpack address is 0x27 with solder-bridge
 * address pins left unbridged. Provisioned through the packet artifact.
 */
#define ACCESS_GATE_LCD_ADDR PACKET_LCD_I2C_ADDRESS

/**
 * @brief UART peripheral used by the RYLR998 transceiver.
 *
 * The RYLR998 connects to UART1 through the Pico 2 header. All AT
 * command traffic flows over this byte stream.
 */
#define ACCESS_GATE_UART uart1

/**
 * @brief UART TX GPIO pin number to the RYLR998 RX input.
 */
#define ACCESS_GATE_UART_TX 8u

/**
 * @brief UART RX GPIO pin number from the RYLR998 TX output.
 */
#define ACCESS_GATE_UART_RX 9u

/**
 * @brief UART baud rate negotiated with the RYLR998.
 *
 * The RYLR998 ships with a 115200 baud default and must be matched on
 * both the edge device and the security desk.
 */
#define ACCESS_GATE_UART_BAUD 115200u

/**
 * @brief RYLR998 network identifier shared by all classroom radios.
 *
 * Every gate and the security desk must program the same network
 * identifier or no frames are delivered over the air.
 */
#define ACCESS_GATE_NETWORK_ID 18u

/**
 * @brief Fixed request frame size in bytes.
 */
#define ACCESS_GATE_FRAME_SIZE PACKET_FRAME_SIZE

/**
 * @brief Number of PIN digits held by the keypad accumulator.
 */
#define ACCESS_GATE_PIN_LENGTH PACKET_PIN_LENGTH

/**
 * @brief Time to wait for a desk grant before annunciating DENIED.
 */
#define ACCESS_GATE_AUTH_WAIT_MS PACKET_AUTH_WAIT_MS

/**
 * @brief Servo pulse width in microseconds that seals the deadbolt.
 */
#define ACCESS_GATE_SERVO_LOCK_PULSE_US PACKET_SERVO_LOCK_PULSE_US

/**
 * @brief Servo pulse width in microseconds that opens the deadbolt.
 */
#define ACCESS_GATE_SERVO_OPEN_PULSE_US PACKET_SERVO_OPEN_PULSE_US

/**
 * @brief Red denied LED GPIO pin number.
 */
#define ACCESS_GATE_RED_LED_PIN 16u

/**
 * @brief Yellow pending LED GPIO pin number.
 */
#define ACCESS_GATE_YELLOW_LED_PIN 17u

/**
 * @brief Green granted LED GPIO pin number.
 */
#define ACCESS_GATE_GREEN_LED_PIN 18u

/**
 * @brief Request-to-exit push-button GPIO pin number.
 */
#define ACCESS_GATE_BUTTON_PIN 15u

/**
 * @brief Deadbolt servo PWM GPIO pin number.
 */
#define ACCESS_GATE_SERVO_PIN 14u

/**
 * @brief Infrared receiver GPIO pin number.
 */
#define ACCESS_GATE_IR_PIN 5u

/**
 * @brief Lowest safe vault temperature in tenths of a degree Celsius.
 */
#define ACCESS_GATE_TEMP_MIN_TENTHS (-50)

/**
 * @brief Highest safe vault temperature in tenths of a degree Celsius.
 */
#define ACCESS_GATE_TEMP_MAX_TENTHS 100

/**
 * @brief Provisioned gate node identifier.
 */
#define ACCESS_GATE_NODE_ID PACKET_NODE_ID

/**
 * @brief Provisioned security desk LoRa address.
 */
#define ACCESS_GATE_HUB_ADDRESS PACKET_HUB_ADDRESS

#endif // ACCESS_GATE_H
