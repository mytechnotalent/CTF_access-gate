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
// File:    radio.h
// Desc:    Declares the RYLR998 UART AT-command interface and rcv parser.
// Created: 2026

#ifndef RADIO_H
#define RADIO_H

#include "hardware/uart.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Maximum RYLR998 AT command length accepted by the builder.
 *
 * Covers the address, length, and payload fields plus the CRLF trailer.
 */
#define RADIO_AT_CMD_MAX_LEN 256u

/**
 * @brief Capacity of the line accumulator including its terminator.
 */
#define RADIO_LINE_BUF_LEN (RADIO_AT_CMD_MAX_LEN + 1u)

/**
 * @brief Maximum received payload length accepted by the +RCV parser.
 *
 * The RYLR998 advertises up to 240-byte payloads; the classroom schema
 * keeps frames at the fixed telemetry size plus headroom.
 */
#define RADIO_RCV_MAX_LEN 256u

/**
 * @brief Radio result codes returned by the AT interface.
 *
 * These values let the monitor distinguish a clean transmit or parse
 * from an overlong frame or a malformed inbound line.
 */
typedef enum radio_result {
    RADIO_RESULT_OK = 0,
    RADIO_RESULT_OVERSIZE = 1,
    RADIO_RESULT_PARSE_ERROR = 2,
    RADIO_RESULT_UART_ERROR = 3,
} radio_result_t;

/**
 * @brief One decoded inbound +RCV report.
 *
 * The sender address and payload are read verbatim from the wire with no
 * cryptographic authentication. This is the spoofable identity author
 * exploited in the classroom injection exercise.
 */
typedef struct radio_rcv {
    /**
     * @brief Sender LoRa node address as reported by the radio.
     */
    uint16_t sender;
    /**
     * @brief Number of payload bytes reported by the radio.
     */
    size_t len;
    /**
     * @brief ASCII payload bytes decoded from the +RCV line.
     */
    char payload[RADIO_RCV_MAX_LEN];
    /**
     * @brief RSSI value reported by the radio in dBm.
     */
    int16_t rssi;
    /**
     * @brief Signal-to-noise ratio reported by the radio in dB.
     */
    int8_t snr;
} radio_rcv_t;

/**
 * @brief Initialize the RYLR998 UART interface.
 *
 * Configures the transceiver UART at the RYLR998 default baud rate and
 * clears any lingering FIFO garbage from the bus.
 *
 * @param uart Pointer to the UART peripheral the radio is wired to.
 * @return bool true when initialization completed.
 */
bool radio_init(uart_inst_t *uart);

/**
 * @brief Build a complete AT+SEND command for one telemetry frame.
 *
 * Emits AT+SEND=<hex-address>,<length>=<payload><CRLF> into the caller
 * buffer and returns false when the command would overflow the limit.
 *
 * @param address The target node address in hex.
 * @param payload Pointer to fixed-size frame bytes.
 * @param len Number of payload bytes to transmit.
 * @param out Pointer to mutable command buffer.
 * @param out_len Capacity of the command buffer in bytes.
 * @return radio_result_t Detailed command-building outcome.
 */
radio_result_t radio_build_send_cmd(uint16_t address, const uint8_t *payload,
                                    size_t len, char *out, size_t out_len);

/**
 * @brief Transmit one fixed-size telemetry frame over the transceiver.
 *
 * Builds the AT+SEND command and writes it in a single UART burst.
 *
 * @param uart Pointer to the UART peripheral the radio is wired to.
 * @param payload Pointer to fixed-size frame bytes.
 * @param len Number of payload bytes to transmit.
 * @return radio_result_t Detailed transmit outcome.
 */
radio_result_t radio_send_frame(uart_inst_t *uart, const uint8_t *payload,
                                size_t len);

/**
 * @brief Parse one raw +RCV line into a structured report.
 *
 * Accepts +RCV=<hex-address>,<length>,<payload>,<rssi>,<snr> with the
 * RSSI and SNR fields treated as optional. Rejects malformed or
 * overlong lines.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param out Pointer to mutable report to fill.
 * @return radio_result_t Detailed parse outcome.
 */
radio_result_t radio_parse_rcv(const char *line, radio_rcv_t *out);

/**
 * @brief Report whether a received report claims a given node address.
 *
 * Compares the sender field only. Security note: the field is read from
 * the unauthenticated wire, so this check is trivially spoofable.
 *
 * @param frame Pointer to a decoded inbound report.
 * @param address Node address being asserted.
 * @return bool true when the reported sender matches the asserted node.
 */
bool radio_frame_is_from(const radio_rcv_t *frame, uint16_t address);

/**
 * @brief Service one inbound UART character and detect a complete line.
 *
 * The RYLR998 emits +RCV reports terminated by CRLF. This state-machine
 * step buffers characters and returns true exactly once a full line is
 * ready to be parsed.
 *
 * @param uart Pointer to the UART peripheral the radio is wired to.
 * @param line Pointer to a mutable line buffer of at least RADIO_LINE_BUF_LEN bytes.
 * @param line_len Pointer to the current accumulated line length.
 * @return bool true when a complete CRLF-terminated line is available.
 */
bool radio_line_pump(uart_inst_t *uart, char *line, size_t *line_len);

#endif // RADIO_H