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
// File:    sensor.c
// Desc:    Implements the DHT11 one-wire sampling state machine and the
//          compact JSON telemetry frame formatter.
// Created: 2026

#include "access_gate.h"
#include "sensor.h"
#include "hardware/gpio.h"
#include "pico/time.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief Module-ready flag.
 *
 * Set to true by sensor_init() after the DHT11 data GPIO is configured.
 * sensor_read() returns a policy error when this flag is not set.
 */
static bool g_sensor_ready;

/**
 * @brief Wait for the sampled pin level to change away from a value.
 *
 * Busy-polls the DHT11 data line until a different level is observed or
 * the caller's timeout elapses.
 *
 * @param level Pin level being escaped.
 * @param timeout_us Maximum time to wait in microseconds.
 * @return bool true when the level changed before timeout.
 */
static bool wait_while_level(int level, uint32_t timeout_us) {
    uint64_t deadline;
    deadline = time_us_64() + (uint64_t)timeout_us;
    while ((int)gpio_get(ACCESS_GATE_DHT_PIN) == level) {
        if (time_us_64() >= deadline) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Measure the duration of a high pulse on the data line.
 *
 * Samples the line until it drops back low or the timeout elapses.
 * Returns zero to signal that the pulse never terminated.
 *
 * @param timeout_us Maximum high-pulse duration in microseconds.
 * @return uint16_t Measured pulse width in microseconds, or zero.
 */
static uint16_t measure_high_width(uint32_t timeout_us) {
    uint64_t start;
    start = time_us_64();
    while ((int)gpio_get(ACCESS_GATE_DHT_PIN) == 1) {
        if (time_us_64() > (start + (uint64_t)timeout_us)) {
            return 0u;
        }
    }
    return (uint16_t)(time_us_64() - start);
}

/**
 * @brief Decode one 8-bit response byte from high-pulse widths.
 *
 * @param bits Pointer to 40 high-pulse widths.
 * @param index Byte index to decode.
 * @return uint8_t Decoded byte value.
 */
static uint8_t dht_decode_byte(const uint16_t bits[SENSOR_BIT_COUNT],
                               uint8_t index) {
    uint8_t value = 0u;
    uint8_t b;
    for (b = 0u; b < 8u; ++b) {
        value = (uint8_t)(value << 1u);
        if (bits[(size_t)index * 8u + b] >= SENSOR_ONE_THRESHOLD_US) {
            value = (uint8_t)(value | 1u);
        }
    }
    return value;
}

/**
 * @brief Decode all five response bytes from the bit widths.
 *
 * @param bits Pointer to 40 high-pulse widths.
 * @param bytes Pointer to mutable five-byte output array.
 * @return void
 */
static void dht_decode_bytes(const uint16_t bits[SENSOR_BIT_COUNT],
                             uint8_t *bytes) {
    uint8_t i;
    for (i = 0u; i < SENSOR_BYTE_COUNT; ++i) {
        bytes[i] = dht_decode_byte(bits, i);
    }
}

/**
 * @brief Validate the DHT11 response checksum.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @return bool true when the checksum byte matches.
 */
static bool dht_checksum_ok(const uint8_t bytes[SENSOR_BYTE_COUNT]) {
    uint8_t sum = (uint8_t)(bytes[0] + bytes[1] + bytes[2] + bytes[3]);
    return sum == bytes[4];
}

/**
 * @brief Decode the signed tenths temperature from response bytes.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @return int16_t Temperature in tenths of a degree Celsius.
 */
static int16_t dht_temperature(const uint8_t bytes[SENSOR_BYTE_COUNT]) {
    int16_t temp;
    if ((bytes[2] & 0x80u) != 0u) {
        temp = (int16_t)(-(int16_t)(bytes[2] & 0x7Fu) * 10);
    } else {
        temp = (int16_t)bytes[2] * 10;
    }
    return (int16_t)(temp + bytes[3]);
}

/**
 * @brief Fill a reading from validated response bytes.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @param out Pointer to mutable reading to fill.
 * @return void
 */
static void dht_fill(const uint8_t bytes[SENSOR_BYTE_COUNT],
                     dht_reading_t *out) {
    out->humidity_tenths = (uint16_t)(bytes[0] * 10u + bytes[1]);
    out->temperature_tenths = dht_temperature(bytes);
    out->valid = true;
}

bool dht_parse_bits(const uint16_t bits[SENSOR_BIT_COUNT], dht_reading_t *out) {
    uint8_t bytes[SENSOR_BYTE_COUNT];
    if ((bits == NULL) || (out == NULL)) {
        return false;
    }
    dht_decode_bytes(bits, bytes);
    if (!dht_checksum_ok(bytes)) {
        return false;
    }
    dht_fill(bytes, out);
    return true;
}

bool sensor_climate_ok(const dht_reading_t *reading) {
    if (reading == NULL || !reading->valid) {
        return false;
    }
    if (reading->temperature_tenths < ACCESS_GATE_TEMP_MIN_TENTHS) {
        return false;
    }
    return reading->temperature_tenths <= ACCESS_GATE_TEMP_MAX_TENTHS;
}

bool sensor_init(void) {
    g_sensor_ready = true;
    gpio_init(ACCESS_GATE_DHT_PIN);
    gpio_set_dir(ACCESS_GATE_DHT_PIN, GPIO_IN);
    gpio_pull_up(ACCESS_GATE_DHT_PIN);
    gpio_put(ACCESS_GATE_DHT_PIN, 1);
    return true;
}

void sensor_deinit(void) {
    g_sensor_ready = false;
}

/**
 * @brief Drive the host start pulse and release the data line.
 *
 * @param void No parameters.
 * @return void
 */
static void dht_start(void) {
    gpio_put(ACCESS_GATE_DHT_PIN, 0);
    gpio_set_dir(ACCESS_GATE_DHT_PIN, GPIO_OUT);
    sleep_us(SENSOR_HOST_PULSE_US);
    gpio_put(ACCESS_GATE_DHT_PIN, 1);
    gpio_set_dir(ACCESS_GATE_DHT_PIN, GPIO_IN);
    gpio_pull_up(ACCESS_GATE_DHT_PIN);
}

/**
 * @brief Wait for the three response handshake edges.
 *
 * @param void No parameters.
 * @return sensor_result_t SENSOR_RESULT_OK or SENSOR_RESULT_TIMEOUT.
 */
static sensor_result_t dht_wait_response(void) {
    if (!wait_while_level(1, SENSOR_EDGE_TIMEOUT_US)) {
        return SENSOR_RESULT_TIMEOUT;
    }
    if (!wait_while_level(0, SENSOR_EDGE_TIMEOUT_US)) {
        return SENSOR_RESULT_TIMEOUT;
    }
    if (!wait_while_level(1, SENSOR_EDGE_TIMEOUT_US)) {
        return SENSOR_RESULT_TIMEOUT;
    }
    return SENSOR_RESULT_OK;
}

/**
 * @brief Sample the 40 high-pulse widths of the response.
 *
 * @param bits Pointer to mutable 40-entry width array.
 * @return sensor_result_t SENSOR_RESULT_OK or SENSOR_RESULT_TIMEOUT.
 */
static sensor_result_t dht_read_bits(uint16_t bits[SENSOR_BIT_COUNT]) {
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        if (!wait_while_level(0, SENSOR_EDGE_TIMEOUT_US)) {
            return SENSOR_RESULT_TIMEOUT;
        }
        bits[i] = measure_high_width(SENSOR_EDGE_TIMEOUT_US);
        if (bits[i] == 0u) {
            return SENSOR_RESULT_TIMEOUT;
        }
    }
    return SENSOR_RESULT_OK;
}

/**
 * @brief Run the start pulse, handshake, and bit sampling.
 *
 * @param bits Pointer to mutable 40-entry width array.
 * @return sensor_result_t SENSOR_RESULT_OK or SENSOR_RESULT_TIMEOUT.
 */
static sensor_result_t dht_fetch_bits(uint16_t bits[SENSOR_BIT_COUNT]) {
    sensor_result_t rc;
    dht_start();
    rc = dht_wait_response();
    if (rc != SENSOR_RESULT_OK) {
        return rc;
    }
    return dht_read_bits(bits);
}

sensor_result_t sensor_read(dht_reading_t *out) {
    uint16_t bits[SENSOR_BIT_COUNT];
    sensor_result_t rc;
    if (!g_sensor_ready || (out == NULL)) {
        return SENSOR_RESULT_POLICY_ERROR;
    }
    rc = dht_fetch_bits(bits);
    if (rc != SENSOR_RESULT_OK) return rc;
    return dht_parse_bits(bits, out) ? SENSOR_RESULT_OK
                                     : SENSOR_RESULT_CRC_ERROR;
}

/**
 * @brief Format the JSON telemetry body into the frame buffer.
 *
 * @param reading Pointer to the decoded DHT11 reading.
 * @param seq Monotonic transmit sequence number.
 * @param out Pointer to mutable frame buffer.
 * @return int Number of characters written.
 */
static int format_frame(const dht_reading_t *reading, uint16_t seq, char *out) {
    return snprintf(out, ACCESS_GATE_FRAME_SIZE,
                    "{\"n\":%u,\"s\":%u,\"t\":%d,\"h\":%u}",
                    (unsigned)PACKET_NODE_ID, (unsigned)seq,
                    (int)reading->temperature_tenths,
                    (unsigned)reading->humidity_tenths);
}

size_t sensor_build_frame(const dht_reading_t *reading, uint16_t seq, char *out,
                          size_t out_len) {
    int n;
    if ((reading == NULL) || (out == NULL) ||
        (out_len < ACCESS_GATE_FRAME_SIZE)) {
        return 0u;
    }
    n = format_frame(reading, seq, out);
    memset(&out[n], 0, ACCESS_GATE_FRAME_SIZE - (size_t)n);
    return (size_t)n;
}