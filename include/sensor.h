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
// File:    sensor.h
// Desc:    Declares the DHT11 one-wire state machine and telemetry frame
//          formatter for RP2350 firmware.
// Created: 2026

#ifndef SENSOR_H
#define SENSOR_H

#include "packet_artifact.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Number of data bits in a DHT11 response frame.
 *
 * The DHT11 returns 40 bits: 8 humidity integer, 8 humidity decimal,
 * 8 temperature integer, 8 temperature decimal, and 8 checksum.
 */
#define SENSOR_BIT_COUNT 40u

/**
 * @brief DHT11 response bit pairs per reading.
 */
#define SENSOR_BYTE_COUNT (SENSOR_BIT_COUNT / 8u)

/**
 * @brief High-pulse width in microseconds above which a bit is a logical one.
 *
 * DHT11 encodes a zero with a ~26-28 us high pulse and a one with a
 * ~70 us high pulse. The 50 us midpoint separates the two classes.
 */
#define SENSOR_ONE_THRESHOLD_US 50u

/**
 * @brief Host start pulse width in microseconds.
 *
 * The DHT11 expects the master to pull the data line low for at least
 * 18 ms before releasing it and sampling the response frame.
 */
#define SENSOR_HOST_PULSE_US 18000u

/**
 * @brief Timeout in microseconds applied to each response edge wait.
 */
#define SENSOR_EDGE_TIMEOUT_US PACKET_DHT_TIMEOUT_US

/**
 * @brief Sensing result codes returned by the one-wire state machine.
 *
 * These values let the monitor distinguish a clean sample from a dead
 * sensor, a checksum failure, or a wired misconfiguration.
 */
typedef enum sensor_result {
    SENSOR_RESULT_OK = 0,
    SENSOR_RESULT_CRC_ERROR = 1,
    SENSOR_RESULT_TIMEOUT = 2,
    SENSOR_RESULT_POLICY_ERROR = 3,
} sensor_result_t;

/**
 * @brief Decoded DHT11 temperature and humidity reading.
 *
 * Integer tenths are used everywhere to avoid floating point on the
 * RP2350 and to keep the wire JSON compact.
 */
typedef struct dht_reading {
    /**
     * @brief Temperature in tenths of a degree Celsius.
     */
    int16_t temperature_tenths;
    /**
     * @brief Relative humidity in tenths of a percent.
     */
    uint16_t humidity_tenths;
    /**
     * @brief True when the reading passed the response checksum.
     */
    bool valid;
} dht_reading_t;

/**
 * @brief Initialize the DHT11 one-wire sensor interface.
 *
 * Configures the data GPIO as an input with pull-up and forces the pin
 * high before any host-start pulse is issued.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool sensor_init(void);

/**
 * @brief Clear the sensor-ready flag.
 *
 * Test and recovery hook that returns the one-wire state machine to the
 * uninitialized policy state.
 *
 * @param void No parameters.
 * @return void
 */
void sensor_deinit(void);

/**
 * @brief Decode a raw 40-bit DHT11 response into a reading.
 *
 * Each array element carries the measured high-pulse width in
 * microseconds. Widths are classed against SENSOR_ONE_THRESHOLD_US and
 * the five 8-bit fields are validated against the DHT11 checksum.
 *
 * @param bits Pointer to 40 high-pulse widths.
 * @param out Pointer to mutable reading to fill.
 * @return bool true when the checksum validates and the reading is sane.
 */
bool dht_parse_bits(const uint16_t bits[SENSOR_BIT_COUNT], dht_reading_t *out);

/**
 * @brief Classify a reading against the vault environmental interlock band.
 *
 * Pure classifier used by the gate state machine before it releases the
 * deadbolt. A reading that failed its checksum is never safe, and a
 * reading outside ACCESS_GATE_TEMP_MIN_TENTHS to ACCESS_GATE_TEMP_MAX_TENTHS
 * is out of band.
 *
 * @param reading Pointer to the decoded DHT11 reading.
 * @return bool true only when the reading is valid and inside the safe band.
 */
bool sensor_climate_ok(const dht_reading_t *reading);

/**
 * @brief Execute one full DHT11 one-wire transaction.
 *
 * Drives the host-start pulse, samples the 40 response bits, and runs
 * the parse and checksum path. On any edge timeout the sample returns
 * SENSOR_RESULT_TIMEOUT.
 *
 * @param out Pointer to mutable reading to fill.
 * @return sensor_result_t Detailed sampling outcome for the caller.
 */
sensor_result_t sensor_read(dht_reading_t *out);

/**
 * @brief Format a reading as the compact telemetry JSON frame.
 *
 * Writes a fixed-shape frame such as {"n":7,"s":12,"t":235,"h":610}
 * into the caller buffer and NUL pads up to ACCESS_GATE_FRAME_SIZE.
 *
 * @param reading Pointer to the decoded reading.
 * @param seq Monotonic transmit sequence number.
 * @param out Pointer to mutable fixed-size frame buffer.
 * @param out_len Capacity of the frame buffer in bytes.
 * @return size_t Length of the JSON body written before padding.
 */
size_t sensor_build_frame(const dht_reading_t *reading, uint16_t seq, char *out,
                          size_t out_len);

#endif // SENSOR_H