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
// File:    radio.c
// Desc:    Implements the RYLR998 AT command builder, the +RCV parser,
//          and the inbound line state machine.
// Created: 2026

#include "access_gate.h"
#include "radio.h"
#include "hardware/gpio.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdio.h>
#include <string.h>

/**
 * @brief Return the value of one hexadecimal ASCII digit.
 *
 * @param ch Input character.
 * @return int Digit value, or -1 when the character is not hexadecimal.
 */
static int hex_digit(char ch) {
    if ((ch >= '0') && (ch <= '9')) {
        return (int)(ch - '0');
    }
    if ((ch >= 'a') && (ch <= 'f')) {
        return (int)(ch - 'a') + 10;
    }
    if ((ch >= 'A') && (ch <= 'F')) {
        return (int)(ch - 'A') + 10;
    }
    return -1;
}

/**
 * @brief Return true when a character is an ASCII decimal digit.
 *
 * @param ch Input character.
 * @return bool true when the character is a digit.
 */
static bool digit_char(char ch) {
    return (ch >= '0') && (ch <= '9');
}

/**
 * @brief Parse a hexadecimal field advancing the index.
 *
 * @param s Pointer to NUL-terminated input.
 * @param i Pointer to current parse index.
 * @return uint32_t Parsed value, or zero when no digit is present.
 */
static uint32_t parse_hex_field(const char *s, size_t *i) {
    uint32_t value = 0u;
    while (hex_digit(s[*i]) >= 0) {
        value = (uint32_t)((value << 4u) | (uint32_t)hex_digit(s[*i]));
        *i += 1u;
    }
    return value;
}

/**
 * @brief Accumulate ASCII decimal digits into a value.
 *
 * @param s Pointer to NUL-terminated input.
 * @param i Pointer to current parse index.
 * @param value Pointer to the accumulator to advance.
 * @return void
 */
static void parse_dec_digits(const char *s, size_t *i, int32_t *value) {
    while (digit_char(s[*i])) {
        *value = *value * 10 + (int32_t)(s[*i] - '0');
        *i += 1u;
    }
}

/**
 * @brief Parse a signed decimal field advancing the index.
 *
 * @param s Pointer to NUL-terminated input.
 * @param i Pointer to current parse index.
 * @return int32_t Parsed value, or zero when no digit is present.
 */
static int32_t parse_dec_field(const char *s, size_t *i) {
    int32_t value = 0;
    bool neg = false;
    if (s[*i] == '-') {
        neg = true;
        *i += 1u;
    }
    parse_dec_digits(s, i, &value);
    return neg ? -value : value;
}

/**
 * @brief Write one AT command and pause for the radio to apply it.
 *
 * @param uart Pointer to the UART peripheral the radio is wired to.
 * @param cmd Pointer to the NUL-terminated command text.
 * @return void
 */
static void radio_send_at(uart_inst_t *uart, const char *cmd) {
    uart_write_blocking(uart, (const uint8_t *)cmd, strlen(cmd));
    sleep_ms(100);
}

/**
 * @brief Program the node address and network identifier.
 *
 * @param uart Pointer to the UART peripheral the radio is wired to.
 * @return void
 */
static void radio_provision(uart_inst_t *uart) {
    char cmd[RADIO_AT_CMD_MAX_LEN];
    snprintf(cmd, sizeof(cmd), "AT+ADDRESS=%u\r\n", (unsigned)PACKET_NODE_ID);
    radio_send_at(uart, cmd);
    snprintf(cmd, sizeof(cmd), "AT+NETWORKID=%u\r\n",
             (unsigned)ACCESS_GATE_NETWORK_ID);
    radio_send_at(uart, cmd);
}

bool radio_init(uart_inst_t *uart) {
    uart_init(uart, ACCESS_GATE_UART_BAUD);
    gpio_set_function(ACCESS_GATE_UART_TX, GPIO_FUNC_UART);
    gpio_set_function(ACCESS_GATE_UART_RX, GPIO_FUNC_UART);
    uart_set_fifo_enabled(uart, true);
    radio_provision(uart);
    return true;
}

/**
 * @brief Validate the argument pointers and payload size for AT+SEND.
 *
 * @param payload Pointer to fixed-size frame bytes.
 * @param out Pointer to mutable command buffer.
 * @param len Number of payload bytes.
 * @return radio_result_t RADIO_RESULT_OK or the failure code.
 */
static radio_result_t validate_send_args(const uint8_t *payload, const char *out,
                                         size_t len) {
    if ((payload == NULL) || (out == NULL)) {
        return RADIO_RESULT_PARSE_ERROR;
    }
    if (len > RADIO_RCV_MAX_LEN) {
        return RADIO_RESULT_OVERSIZE;
    }
    return RADIO_RESULT_OK;
}

/**
 * @brief Format one AT+SEND command into the output buffer.
 *
 * @param address Target node address.
 * @param payload Pointer to frame bytes.
 * @param len Number of payload bytes.
 * @param out Pointer to mutable command buffer.
 * @param out_len Capacity of the command buffer.
 * @return bool true when the command fit the buffer.
 */
static bool format_send_cmd(uint16_t address, const uint8_t *payload,
                            size_t len, char *out, size_t out_len) {
    int n;
    n = snprintf(out, out_len, "AT+SEND=%04X,%u,%s\r\n", (unsigned)address,
                 (unsigned)len, (const char *)payload);
    return (n > 0) && ((size_t)n < out_len);
}

radio_result_t radio_build_send_cmd(uint16_t address, const uint8_t *payload,
                                    size_t len, char *out, size_t out_len) {
    radio_result_t rc;
    rc = validate_send_args(payload, out, len);
    if (rc != RADIO_RESULT_OK) {
        return rc;
    }
    if (!format_send_cmd(address, payload, len, out, out_len)) {
        return RADIO_RESULT_OVERSIZE;
    }
    return RADIO_RESULT_OK;
}

radio_result_t radio_send_frame(uart_inst_t *uart, const uint8_t *payload,
                                size_t len) {
    char cmd[RADIO_AT_CMD_MAX_LEN];
    radio_result_t rc;
    rc = radio_build_send_cmd(PACKET_HUB_ADDRESS, payload, len, cmd,
                              sizeof(cmd));
    if (rc != RADIO_RESULT_OK) {
        return rc;
    }
    uart_write_blocking(uart, (const uint8_t *)cmd, strlen(cmd));
    return RADIO_RESULT_OK;
}

/**
 * @brief Consume one comma separator.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @return bool true when a comma was consumed.
 */
static bool rcv_expect_comma(const char *line, size_t *i) {
    if (line[*i] != ',') {
        return false;
    }
    *i += 1u;
    return true;
}

/**
 * @brief Parse the +RCV prefix and the node address field.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @param address Pointer to store the parsed node address.
 * @return bool true when the prefix and address parsed.
 */
static bool rcv_parse_addr(const char *line, size_t *i, uint32_t *address) {
    if ((line == NULL) || (strncmp(line, "+RCV=", 5u) != 0)) {
        return false;
    }
    *i = 5u;
    *address = parse_hex_field(line, i);
    return rcv_expect_comma(line, i);
}

/**
 * @brief Parse the declared payload length field.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @param plen Pointer to store the parsed payload length.
 * @return bool true when the length and trailing comma parsed.
 */
static bool rcv_parse_len(const char *line, size_t *i, uint32_t *plen) {
    *plen = (uint32_t)parse_dec_field(line, i);
    return rcv_expect_comma(line, i);
}

/**
 * @brief Parse the header fields and validate the reported sizes.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @param out Pointer to mutable report to fill.
 * @param plen Pointer to store the parsed payload length.
 * @return radio_result_t Detailed header outcome.
 */
static radio_result_t rcv_parse_head(const char *line, size_t *i,
                                     radio_rcv_t *out, uint32_t *plen) {
    uint32_t address;
    if (!rcv_parse_addr(line, i, &address) || !rcv_parse_len(line, i, plen)) {
        return RADIO_RESULT_PARSE_ERROR;
    }
    if ((address > 0xFFFFu) || (*plen > RADIO_RCV_MAX_LEN)) {
        return RADIO_RESULT_OVERSIZE;
    }
    out->sender = (uint16_t)address;
    return RADIO_RESULT_OK;
}

/**
 * @brief Copy the declared payload bytes out of the wire line.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param out Pointer to mutable report to fill.
 * @param i Pointer to current parse index.
 * @param plen Declared payload byte length.
 * @return bool true when exactly plen bytes were copied.
 */
static bool rcv_copy_payload(const char *line, radio_rcv_t *out, size_t *i,
                             uint32_t plen) {
    size_t k = 0u;
    while ((k < plen) && (line[*i] != '\0')) {
        out->payload[k] = line[*i];
        ++k;
        *i += 1u;
    }
    out->len = k;
    out->payload[k] = '\0';
    return k == plen;
}

/**
 * @brief Parse an optional signed decimal tail field.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @param fallback Value to use when the field is absent.
 * @return int16_t Parsed value, or the fallback.
 */
static int16_t rcv_take_tail(const char *line, size_t *i, int16_t fallback) {
    if (line[*i] != ',') {
        return fallback;
    }
    *i += 1u;
    return (int16_t)parse_dec_field(line, i);
}

/**
 * @brief Parse the optional RSSI and SNR tail fields.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param i Pointer to current parse index.
 * @param out Pointer to mutable report to fill.
 * @return void
 */
static void rcv_parse_tail(const char *line, size_t *i, radio_rcv_t *out) {
    out->rssi = rcv_take_tail(line, i, 0);
    out->snr = (int8_t)rcv_take_tail(line, i, 0);
}

/**
 * @brief Copy the payload and parse the tail fields.
 *
 * @param line Pointer to NUL-terminated wire line.
 * @param out Pointer to mutable report to fill.
 * @param i Pointer to current parse index.
 * @param plen Declared payload byte length.
 * @return radio_result_t Detailed outcome.
 */
static radio_result_t rcv_finish(const char *line, radio_rcv_t *out, size_t *i,
                                 uint32_t plen) {
    if (!rcv_copy_payload(line, out, i, plen)) {
        return RADIO_RESULT_PARSE_ERROR;
    }
    rcv_parse_tail(line, i, out);
    return RADIO_RESULT_OK;
}

radio_result_t radio_parse_rcv(const char *line, radio_rcv_t *out) {
    size_t i = 0u;
    uint32_t plen;
    radio_result_t rc;
    if (out == NULL) {
        return RADIO_RESULT_PARSE_ERROR;
    }
    rc = rcv_parse_head(line, &i, out, &plen);
    if (rc != RADIO_RESULT_OK) return rc;
    return rcv_finish(line, out, &i, plen);
}

bool radio_frame_is_from(const radio_rcv_t *frame, uint16_t address) {
    return frame->sender == address;
}

/**
 * @brief Fold one received character into the line accumulator.
 *
 * @param line Pointer to mutable line buffer.
 * @param line_len Pointer to current accumulated line length.
 * @param ch Received character.
 * @return bool true when the character completed a line.
 */
static bool pump_char(char *line, size_t *line_len, int ch) {
    if (ch == '\n') {
        line[*line_len] = '\0';
        *line_len = 0u;
        return true;
    }
    if ((ch != '\r') && (*line_len < RADIO_AT_CMD_MAX_LEN)) {
        line[*line_len] = (char)ch;
        *line_len += 1u;
    }
    return false;
}

bool radio_line_pump(uart_inst_t *uart, char *line, size_t *line_len) {
    int ch;
    while (uart_is_readable(uart)) {
        ch = uart_getc(uart);
        if (pump_char(line, line_len, ch)) {
            return true;
        }
    }
    return false;
}