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
// File:    ir_remote.c
// Desc:    Implements the VS1838B infrared receiver and NEC remote decoder.
// Created: 2026

#include "pico/stdlib.h"
#include "pico/time.h"
#include "access_gate.h"
#include "ir_remote.h"
#include "hardware/gpio.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Maximum wait in microseconds for one receiver edge.
 */
#define IR_REMOTE_EDGE_TIMEOUT_US 30000u

/**
 * @brief Validate the NEC leader mark duration.
 *
 * @param mark Leader mark duration in microseconds.
 * @return bool true when the leader mark is inside the valid band.
 */
static bool ir_leader_valid(uint16_t mark) {
    return (mark >= IR_NEC_LEADER_MARK_MIN_US) &&
           (mark <= IR_NEC_LEADER_MARK_MAX_US);
}

/**
 * @brief Validate a NEC bit mark duration.
 *
 * @param mark Bit mark duration in microseconds.
 * @return bool true when the bit mark is inside the valid band.
 */
static bool ir_mark_valid(uint16_t mark) {
    return (mark >= IR_NEC_BIT_MARK_MIN_US) &&
           (mark <= IR_NEC_BIT_MARK_MAX_US);
}

/**
 * @brief Classify a NEC bit space duration as a zero or a one.
 *
 * @param space Bit space duration in microseconds.
 * @return int Decoded bit value, or -1 when the space is out of band.
 */
static int ir_classify_space(uint16_t space) {
    if (space <= IR_NEC_ZERO_SPACE_MAX_US) {
        return 0;
    }
    if (space >= IR_NEC_ONE_SPACE_MIN_US) {
        return 1;
    }
    return -1;
}

/**
 * @brief Decode one LSB-first NEC bit from its mark and space.
 *
 * @param pulses Pointer to alternating mark and space durations.
 * @param index Zero-based bit index in the frame.
 * @return int Decoded bit value, or -1 when the pair is malformed.
 */
static int ir_bit_value(const uint16_t *pulses, uint8_t index) {
    uint16_t mark = pulses[2u + (size_t)index * 2u];
    uint16_t space = pulses[3u + (size_t)index * 2u];
    if (!ir_mark_valid(mark)) {
        return -1;
    }
    return ir_classify_space(space);
}

/**
 * @brief Accumulate one decoded bit into the frame word.
 *
 * @param pulses Pointer to alternating mark and space durations.
 * @param index Zero-based bit index in the frame.
 * @param bits Pointer to mutable frame word under construction.
 * @return bool true when the bit decoded cleanly.
 */
static bool ir_accumulate_bit(const uint16_t *pulses, uint8_t index,
                              uint32_t *bits) {
    int bit = ir_bit_value(pulses, index);
    if (bit < 0) {
        return false;
    }
    *bits |= (uint32_t)bit << index;
    return true;
}

/**
 * @brief Decode all thirty-two LSB-first bits of a NEC frame.
 *
 * @param pulses Pointer to alternating mark and space durations.
 * @param bits Pointer to mutable frame word under construction.
 * @return bool true when every mark and space decoded cleanly.
 */
static bool ir_decode_bits(const uint16_t *pulses, uint32_t *bits) {
    uint8_t i;
    *bits = 0u;
    for (i = 0u; i < 32u; ++i) {
        if (!ir_accumulate_bit(pulses, i, bits)) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Extract one byte from a decoded NEC frame word.
 *
 * @param bits Decoded frame word.
 * @param shift Right shift in bits to the target byte.
 * @return uint8_t Extracted byte value.
 */
static uint8_t ir_byte(uint32_t bits, uint8_t shift) {
    return (uint8_t)((bits >> shift) & 0xFFu);
}

/**
 * @brief Validate the address and command complement pairs.
 *
 * @param bits Decoded frame word.
 * @return bool true when both inverse-byte checks pass.
 */
static bool ir_bytes_ok(uint32_t bits) {
    if (ir_byte(bits, 0u) != (uint8_t)~ir_byte(bits, 8u)) {
        return false;
    }
    return ir_byte(bits, 16u) == (uint8_t)~ir_byte(bits, 24u);
}

/**
 * @brief Populate a decoded command from a validated frame word.
 *
 * @param bits Decoded frame word.
 * @param out Pointer to mutable decoded command.
 * @return bool true when the frame carries a valid command.
 */
static bool ir_fill_command(uint32_t bits, ir_command_t *out) {
    if (!ir_bytes_ok(bits)) {
        return false;
    }
    out->valid = true;
    out->address = ir_byte(bits, 0u);
    out->command = ir_byte(bits, 16u);
    return true;
}

/**
 * @brief Wait for the receiver pin to leave a given level.
 *
 * @param level Pin level being escaped.
 * @param timeout_us Maximum time to wait in microseconds.
 * @return bool true when the level changed before the timeout.
 */
static bool ir_wait_level(int level, uint32_t timeout_us) {
    uint64_t deadline = time_us_64() + (uint64_t)timeout_us;
    while ((int)gpio_get(ACCESS_GATE_IR_PIN) == level) {
        if (time_us_64() >= deadline) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Measure how long the receiver pin holds a level.
 *
 * @param level Pin level being timed.
 * @param timeout_us Maximum level duration in microseconds.
 * @return uint32_t Measured duration in microseconds, or zero on timeout.
 */
static uint32_t ir_measure_level(int level, uint32_t timeout_us) {
    uint64_t start = time_us_64();
    while ((int)gpio_get(ACCESS_GATE_IR_PIN) == level) {
        if (time_us_64() > (start + (uint64_t)timeout_us)) {
            return 0u;
        }
    }
    return (uint32_t)(time_us_64() - start);
}

/**
 * @brief Capture one pulse duration and advance the pulse count.
 *
 * @param pulses Pointer to mutable pulse buffer.
 * @param count Pointer to mutable number of stored pulses.
 * @param level Pin level whose duration is measured.
 * @return bool true when a duration was stored.
 */
static bool ir_capture_step(uint16_t *pulses, size_t *count, int level) {
    uint32_t width = ir_measure_level(level, IR_REMOTE_EDGE_TIMEOUT_US);
    if (width == 0u) {
        return false;
    }
    pulses[*count] = (uint16_t)width;
    *count += 1u;
    return true;
}

/**
 * @brief Capture an alternating mark and space pulse train.
 *
 * @param pulses Pointer to mutable pulse buffer.
 * @param max Capacity of the pulse buffer.
 * @return size_t Number of captured pulse durations.
 */
static size_t ir_capture(uint16_t *pulses, size_t max) {
    size_t count = 0u;
    int level = 0;
    if (!ir_wait_level(1, IR_REMOTE_EDGE_TIMEOUT_US)) {
        return 0u;
    }
    while (count < max && ir_capture_step(pulses, &count, level)) {
        level = 1 - level;
    }
    return count;
}

bool ir_remote_init(void) {
    gpio_init(ACCESS_GATE_IR_PIN);
    gpio_set_dir(ACCESS_GATE_IR_PIN, GPIO_IN);
    gpio_pull_up(ACCESS_GATE_IR_PIN);
    return true;
}

bool ir_decode_nec(const uint16_t *pulses, size_t count, ir_command_t *out) {
    uint32_t bits;
    if ((pulses == NULL) || (out == NULL) || (count < IR_NEC_FRAME_PULSES)) {
        return false;
    }
    if (!ir_leader_valid(pulses[0]) || !ir_decode_bits(pulses, &bits)) {
        return false;
    }
    return ir_fill_command(bits, out);
}

bool ir_remote_poll(ir_command_t *out) {
    uint16_t pulses[IR_REMOTE_MAX_PULSES];
    size_t count = ir_capture(pulses, IR_REMOTE_MAX_PULSES);
    return ir_decode_nec(pulses, count, out);
}
