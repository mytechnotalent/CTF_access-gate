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
// File:    ir_remote.h
// Desc:    Declares the VS1838B infrared receiver and NEC remote decoder.
// Created: 2026

#ifndef IR_REMOTE_H
#define IR_REMOTE_H

#include "access_gate.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Maximum number of NEC mark and space durations captured per frame.
 */
#define IR_REMOTE_MAX_PULSES 68u

/**
 * @brief Number of captured durations in one complete NEC frame.
 *
 * The leader mark and space, thirty-two mark and space bit pairs, and the
 * final mark total sixty-seven captured durations. A real receiver never
 * captures the trailing idle space because it exceeds the edge timeout.
 */
#define IR_NEC_FRAME_PULSES 67u

/**
 * @brief NEC leader mark duration lower bound in microseconds.
 */
#define IR_NEC_LEADER_MARK_MIN_US 8000u

/**
 * @brief NEC leader mark duration upper bound in microseconds.
 */
#define IR_NEC_LEADER_MARK_MAX_US 10000u

/**
 * @brief NEC bit mark duration lower bound in microseconds.
 */
#define IR_NEC_BIT_MARK_MIN_US 400u

/**
 * @brief NEC bit mark duration upper bound in microseconds.
 */
#define IR_NEC_BIT_MARK_MAX_US 800u

/**
 * @brief NEC zero space upper bound in microseconds.
 */
#define IR_NEC_ZERO_SPACE_MAX_US 900u

/**
 * @brief NEC one space lower bound in microseconds.
 */
#define IR_NEC_ONE_SPACE_MIN_US 1400u

/**
 * @brief Number of command bits decoded from a NEC frame.
 */
#define IR_NEC_COMMAND_BITS 8u

/**
 * @brief Decoded maintenance remote command.
 *
 * The address and command are read from the wire with no challenge and no
 * secret. This is the second unauthenticated control surface that the
 * classroom replay exercise exploits.
 */
typedef struct ir_command {
    /**
     * @brief True when a frame decoded to a valid command.
     */
    bool valid;
    /**
     * @brief Eight-bit remote address code.
     */
    uint8_t address;
    /**
     * @brief Eight-bit remote command code.
     */
    uint8_t command;
} ir_command_t;

/**
 * @brief Initialize the VS1838B infrared receiver input.
 *
 * Configures the receiver GPIO as an input with the internal pull-up
 * enabled, because the demodulator idles high and pulls low on a mark.
 *
 * @param void No parameters.
 * @return bool true when initialization completed.
 */
bool ir_remote_init(void);

/**
 * @brief Decode a captured NEC pulse train into a command.
 *
 * The pulse train alternates mark and space durations in microseconds,
 * beginning with the 9 ms leader mark. The decoder validates the leader,
 * classifies thirty-two bits, and rejects a frame whose command byte is
 * not the bitwise complement of its inverse byte.
 *
 * @param pulses Pointer to alternating mark and space durations.
 * @param count Number of captured durations.
 * @param out Pointer to mutable decoded command.
 * @return bool true when a valid NEC command decoded.
 */
bool ir_decode_nec(const uint16_t *pulses, size_t count, ir_command_t *out);

/**
 * @brief Capture one NEC frame from the receiver and decode it.
 *
 * Times the receiver edges, fills the pulse buffer, and runs the decoder.
 * Returns false when no frame arrives or the frame is malformed.
 *
 * @param out Pointer to mutable decoded command.
 * @return bool true when a valid NEC command decoded.
 */
bool ir_remote_poll(ir_command_t *out);

#endif // IR_REMOTE_H
