/**
 * FILE: test_access_gate_and_security.c
 *
 * DESCRIPTION:
 * Comprehensive test suite for the RP2350 Access Gate: provisioning
 * constants, packet artifact, CRC, DHT11 interlock classification, display
 * formatting, RYLR998 AT command building, +RCV parsing, the NEC keypad
 * PIN accumulator, the authenticated authorization record with its
 * anti-replay window, and the gate state-machine ticks.
 *
 * BRIEF:
 * Native unit test runner for access-gate.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#include "harness.h"
#include "mock/pico/stdlib.h"
#include "mock/pico/time.h"
#include "mock/hardware/gpio.h"
#include "mock/hardware/i2c.h"
#include "mock/hardware/pwm.h"
#include "mock/hardware/uart.h"
#include "access_gate.h"
#include "button.h"
#include "crc.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "keypad.h"
#include "auth.h"
#include "monitor.h"
#include "packet_artifact.h"
#include <stdio.h>
#include <string.h>

#undef SENSOR_HOST_PULSE_US
#define SENSOR_HOST_PULSE_US 0u

#include "../src/sensor.c"
#include "../src/crc.c"
#include "../src/display.c"
#include "../src/radio.c"
#include "../src/keypad.c"
#include "../src/auth.c"
#include "../src/monitor.c"

/**
 * @brief Simulated DHT11 high-pulse widths for the canonical reading.
 *
 * Bytes decoded: humidity 61, humidity-decimal 0, temperature 23,
 * temperature-decimal 0, checksum 0x54.
 */
static const uint16_t s_widths[SENSOR_BIT_COUNT] = {
    26u, 26u, 70u, 70u, 70u, 70u, 26u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 26u, 26u, 70u, 26u, 70u, 70u, 70u,
    26u, 26u, 26u, 26u, 26u, 26u, 26u, 26u,
    26u, 70u, 26u, 70u, 26u, 70u, 26u, 26u,
};

/**
 * @brief Fixed field key used by the authorization record tests.
 */
static const uint8_t s_key[CRYPTO_AEAD_KEY_LEN] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
};

/**
 * @brief File-scope GPIO timeline offset scratch buffer.
 */
static uint32_t s_offsets[256];

/**
 * @brief File-scope GPIO timeline level scratch buffer.
 */
static int s_levels[256];

/**
 * @brief File-scope UART transmit capture buffer.
 */
static char s_tx[2048];

/**
 * @brief File-scope raw I2C log scratch buffer.
 */
static uint8_t s_raw[512];

/**
 * @brief File-scope decoded LCD scratch buffer.
 */
static char s_decoded[DISPLAY_LINE_LEN * 4];

/**
 * @brief File-scope first LCD render line buffer.
 */
static char s_line1[DISPLAY_LINE_LEN];

/**
 * @brief File-scope second LCD render line buffer.
 */
static char s_line2[DISPLAY_LINE_LEN];

/**
 * @brief File-scope decoded DHT11 reading.
 */
static dht_reading_t s_reading;

/**
 * @brief File-scope decoded inbound radio report.
 */
static radio_rcv_t s_rcv;

/**
 * @brief File-scope NEC pulse-duration scratch buffer.
 */
static uint16_t s_pulses[IR_REMOTE_MAX_PULSES];

/**
 * @brief File-scope NEC GPIO timeline offset scratch buffer.
 */
static uint32_t s_ir_off[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief File-scope NEC GPIO timeline level scratch buffer.
 */
static int s_ir_lvl[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief Reset every host mock peripheral.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_all(void) {
    mock_timer_reset();
    mock_gpio_reset();
    mock_i2c_reset();
    mock_uart_reset();
    mock_pwm_reset();
    rex_reset();
}

/**
 * @brief Append one timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param level Level to record.
 * @param edge Absolute timestamp in microseconds.
 * @return size_t Updated entry count.
 */
static size_t timeline_pair(uint32_t *offsets, int *levels, size_t n,
                            int level, uint32_t edge) {
    offsets[n] = edge;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Write the four leading DHT11 handshake timeline points.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t timeline_header(uint32_t *offsets, int *levels) {
    size_t n = 0u;
    n = timeline_pair(offsets, levels, n, 1, 0u);
    n = timeline_pair(offsets, levels, n, 0, 30u);
    n = timeline_pair(offsets, levels, n, 1, 110u);
    n = timeline_pair(offsets, levels, n, 0, 190u);
    return n;
}

/**
 * @brief Append the 40 data-bit timeline point pairs.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Updated entry count.
 */
static size_t timeline_bits(uint32_t *offsets, int *levels, size_t n,
                            const uint16_t *widths) {
    uint32_t edge = 190u;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        edge += 50u;
        n = timeline_pair(offsets, levels, n, 1, edge);
        edge += widths[i];
        n = timeline_pair(offsets, levels, n, 0, edge);
    }
    return n;
}

/**
 * @brief Build a DHT11 one-wire waveform timeline from bit widths.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param widths Pointer to 40 high-pulse width values.
 * @return size_t Number of timeline entries written.
 */
static size_t build_timeline(uint32_t *offsets, int *levels,
                             const uint16_t *widths) {
    size_t n = timeline_header(offsets, levels);
    return timeline_bits(offsets, levels, n, widths);
}

/**
 * @brief Combine the high nibbles of two I2C bytes into one display byte.
 *
 * @param hi First raw mock I2C byte.
 * @param lo Second raw mock I2C byte.
 * @return char Decoded display byte.
 */
static char decode_nibble(uint8_t hi, uint8_t lo) {
    uint8_t h = (uint8_t)((hi >> 4u) & 0x0Fu);
    uint8_t l = (uint8_t)((lo >> 4u) & 0x0Fu);
    return (char)((h << 4u) | l);
}

/**
 * @brief Decode 4-bit I2C LCD writes back into display bytes.
 *
 * @param buf Pointer to raw mock I2C byte log.
 * @param n Number of raw log bytes.
 * @param out Pointer to mutable decoded text buffer.
 * @param out_max Capacity of the decoded text buffer.
 * @return size_t Number of decoded display bytes.
 */
static size_t decode_lcd_bytes(const uint8_t *buf, size_t n, char *out,
                               size_t out_max) {
    size_t k = 0u;
    size_t i = 0u;
    while ((i + 4u <= n) && (k + 1u < out_max)) {
        out[k] = decode_nibble(buf[i], buf[i + 2u]);
        ++k;
        i += 4u;
    }
    out[k] = '\0';
    return k;
}

/**
 * @brief Build a 40-bit width array from five response bytes.
 *
 * @param bytes Pointer to five DHT11 response bytes.
 * @param out Pointer to mutable width array of SENSOR_BIT_COUNT entries.
 * @return void
 */
static void build_bits_from_bytes(const uint8_t bytes[SENSOR_BYTE_COUNT],
                                  uint16_t *out) {
    uint8_t b;
    uint8_t bit;
    size_t k = 0u;
    for (b = 0u; b < SENSOR_BYTE_COUNT; ++b) {
        for (bit = 0u; bit < 8u; ++bit) {
            out[k] = ((bytes[b] >> (7u - bit)) & 1u) ? 70u : 26u;
            k += 1u;
        }
    }
}

/**
 * @brief Copy the canonical high-pulse widths into a bit array.
 *
 * @param bits Pointer to mutable 40-entry width array.
 * @return void
 */
static void fill_widths(uint16_t *bits) {
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
}

/**
 * @brief Arm a full DHT11 waveform timeline at a base timestamp.
 *
 * @param widths Pointer to 40 high-pulse width values.
 * @param base_us Absolute base timestamp in microseconds.
 * @return void
 */
static void mock_dht_timeline(const uint16_t *widths, uint64_t base_us) {
    size_t count = build_timeline(s_offsets, s_levels, widths);
    mock_gpio_timeline_begin_at(base_us, s_offsets, s_levels, count,
                                ACCESS_GATE_DHT_PIN);
}

/**
 * @brief Load the canonical LCD render lines into the fixtures.
 *
 * @param void No parameters.
 * @return void
 */
static void load_display_lines(void) {
    strcpy(s_line1, "T:23.0C H:61.0%");
    strcpy(s_line2, "N:07 S:0042 OK");
}

/**
 * @brief Assert the decoded LCD frame buffer contents.
 *
 * @param line1 Expected first-line text.
 * @param line2 Expected second-line text.
 * @return void
 */
static void assert_lcd_frame(const char *line1, const char *line2) {
    size_t count;
    count = mock_i2c_get_log(s_raw, sizeof(s_raw));
    TEST_ASSERT_EQUAL_UINT(136u, (unsigned)count);
    decode_lcd_bytes(s_raw, count, s_decoded, sizeof(s_decoded));
    TEST_ASSERT_EQUAL_UINT8(0x80u, (uint8_t)s_decoded[0]);
    TEST_ASSERT_TRUE(strncmp(line1, &s_decoded[1], strlen(line1)) == 0);
    TEST_ASSERT_EQUAL_UINT8(0xC0u, (uint8_t)s_decoded[17]);
    TEST_ASSERT_TRUE(strncmp(line2, &s_decoded[18], strlen(line2)) == 0);
}

/**
 * @brief Load a canonical valid reading into the fixture.
 *
 * @param void No parameters.
 * @return void
 */
static void load_reading(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
}

/**
 * @brief Assert the GPIO pin and bus provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_pin_constants(void) {
    TEST_ASSERT_EQUAL_UINT(25u, ACCESS_GATE_LED_PIN);
    TEST_ASSERT_EQUAL_UINT(4u, ACCESS_GATE_DHT_PIN);
    TEST_ASSERT_EQUAL_UINT(2u, ACCESS_GATE_I2C_SDA);
    TEST_ASSERT_EQUAL_UINT(3u, ACCESS_GATE_I2C_SCL);
    TEST_ASSERT_EQUAL_UINT(100000u, ACCESS_GATE_I2C_BAUD);
    TEST_ASSERT_EQUAL_UINT(8u, ACCESS_GATE_UART_TX);
    TEST_ASSERT_EQUAL_UINT(9u, ACCESS_GATE_UART_RX);
}

/**
 * @brief Assert the UART, frame, and gate provisioning constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_frame_constants(void) {
    TEST_ASSERT_EQUAL_UINT(115200u, ACCESS_GATE_UART_BAUD);
    TEST_ASSERT_EQUAL_UINT(48u, ACCESS_GATE_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(6u, ACCESS_GATE_PIN_LENGTH);
    TEST_ASSERT_EQUAL_UINT(5000u, ACCESS_GATE_AUTH_WAIT_MS);
    TEST_ASSERT_EQUAL_UINT(PACKET_LCD_I2C_ADDRESS, ACCESS_GATE_LCD_ADDR);
    TEST_ASSERT_EQUAL_UINT(500u, ACCESS_GATE_SERVO_LOCK_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, ACCESS_GATE_SERVO_OPEN_PULSE_US);
}

/**
 * @brief Assert the vault environmental interlock band constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_band_constants(void) {
    TEST_ASSERT_EQUAL_INT(-50, ACCESS_GATE_TEMP_MIN_TENTHS);
    TEST_ASSERT_EQUAL_INT(100, ACCESS_GATE_TEMP_MAX_TENTHS);
}

/**
 * @brief Assert the packet artifact identity constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_ids(void) {
    TEST_ASSERT_EQUAL_STRING("access-gate-packets-demo-v1",
                             PACKET_ARTIFACT_FORMAT);
    TEST_ASSERT_EQUAL_UINT(1u, PACKET_FRAME_VERSION);
    TEST_ASSERT_EQUAL_UINT(7u, PACKET_NODE_ID);
    TEST_ASSERT_EQUAL_HEX16(0x0001u, PACKET_HUB_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(48u, PACKET_FRAME_SIZE);
    TEST_ASSERT_EQUAL_UINT(6u, PACKET_PIN_LENGTH);
    TEST_ASSERT_EQUAL_UINT(5000u, PACKET_AUTH_WAIT_MS);
}

/**
 * @brief Assert the packet artifact frame constants.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_artifact_frame(void) {
    TEST_ASSERT_EQUAL_UINT(500u, PACKET_SERVO_LOCK_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(1500u, PACKET_SERVO_OPEN_PULSE_US);
    TEST_ASSERT_EQUAL_UINT(240u, PACKET_DHT_TIMEOUT_US);
    TEST_ASSERT_EQUAL_UINT(0x27u, PACKET_LCD_I2C_ADDRESS);
    TEST_ASSERT_EQUAL_UINT(256u, PACKET_MAX_RCV_LEN);
    TEST_ASSERT_EQUAL_UINT(48u, (unsigned)sizeof(PACKET_EXAMPLE_FRAME));
    TEST_ASSERT_EQUAL_UINT8(0x7Bu, PACKET_EXAMPLE_FRAME[0]);
}

/**
 * @brief Assert the formatted frame text and zero padding.
 *
 * @param frame Pointer to the formatted frame buffer.
 * @param n Length of the JSON body.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_padding(const char *frame, size_t n, size_t cap) {
    static const char zeros[ACCESS_GATE_FRAME_SIZE] = {0};
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)n);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}", frame);
    TEST_ASSERT_EQUAL_MEMORY(zeros, &frame[n], cap - n);
}

/**
 * @brief Assert frame-builder rejection of null arguments.
 *
 * @param frame Pointer to a frame buffer.
 * @param cap Capacity of the frame buffer.
 * @return void
 */
static void assert_frame_rejects(char *frame, size_t cap) {
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(&s_reading, 0u, NULL, 0u));
    TEST_ASSERT_EQUAL_UINT(0u,
                           (unsigned)sensor_build_frame(NULL, 0u, frame, cap));
}

/**
 * @brief Assert command-builder rejection paths.
 *
 * @param cmd Pointer to a command buffer.
 * @param cap Capacity of the command buffer.
 * @return void
 */
static void assert_build_rejects(char *cmd, size_t cap) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, (const uint8_t *)"abc",
                                           257u, cmd, cap));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_build_send_cmd(0x0001u, NULL, 3u, cmd, cap));
}

/**
 * @brief Parse the canonical comma-laden JSON +RCV line.
 *
 * @param void No parameters.
 * @return radio_result_t Parsed result code.
 */
static radio_result_t parse_json_rcv(void) {
    return radio_parse_rcv("+RCV=0007,29,{\"n\":7,\"s\":0,\"t\":230,\"h\":610}"
                           ",-78,5", &s_rcv);
}

/**
 * @brief Assert +RCV parsing of a comma-laden JSON payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_json(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, parse_json_rcv());
    TEST_ASSERT_EQUAL_HEX16(0x0007u, s_rcv.sender);
    TEST_ASSERT_EQUAL_UINT(29u, (unsigned)s_rcv.len);
    TEST_ASSERT_EQUAL_STRING("{\"n\":7,\"s\":0,\"t\":230,\"h\":610}",
                             s_rcv.payload);
    TEST_ASSERT_EQUAL_INT(-78, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(5, s_rcv.snr);
}

/**
 * @brief Assert +RCV parsing of a short comma-bearing payload.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_comma(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0008,9,{\"a\",\"b\"},-60,3", &s_rcv));
    TEST_ASSERT_EQUAL_HEX16(0x0008u, s_rcv.sender);
    TEST_ASSERT_EQUAL_STRING("{\"a\",\"b\"}", s_rcv.payload);
}

/**
 * @brief Assert +RCV parsing of a frame with no RSSI/SNR tail.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_no_tail(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=0007,2,ok", &s_rcv));
    TEST_ASSERT_EQUAL_INT(0, s_rcv.rssi);
    TEST_ASSERT_EQUAL_INT(0, s_rcv.snr);
}

/**
 * @brief Assert +RCV rejection of null arguments.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_null(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR, radio_parse_rcv(NULL, &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,1,a", NULL));
}

/**
 * @brief Assert +RCV rejection of malformed and oversized lines.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_rcv_rejects(void) {
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("AT+SEND=0001,3,abc", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_parse_rcv("+RCV=0001,300,abcdef", &s_rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0001,5,abc", &s_rcv));
    assert_rcv_null();
}

/**
 * @brief Assert the inbound line pump consumes two CRLF-terminated lines.
 *
 * @param line Pointer to line buffer.
 * @param len Pointer to accumulated length.
 * @return void
 */
static void assert_pump_lines(char *line, size_t *len) {
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("ab", line);
    TEST_ASSERT_TRUE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_STRING("cd", line);
    TEST_ASSERT_FALSE(radio_line_pump(uart0, line, len));
    TEST_ASSERT_EQUAL_UINT(0u, (unsigned)*len);
}

/**
 * @brief Assert the positive display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_ok(void) {
    s_reading.temperature_tenths = 230;
    s_reading.humidity_tenths = 610;
    s_reading.valid = true;
    display_format_lines(&s_reading, 42u, true, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:23.0C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0042 OK", s_line2);
}

/**
 * @brief Assert the negative display formatting path.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_format_fail(void) {
    s_reading.temperature_tenths = -53;
    display_format_lines(&s_reading, 0u, false, s_line1, s_line2);
    TEST_ASSERT_EQUAL_STRING("T:-5.3C H:61.0%", s_line1);
    TEST_ASSERT_EQUAL_STRING("N:07 S:0000 !!", s_line2);
}

/**
 * @brief Build the NEC frame word for address zero and a command.
 *
 * @param command Eight-bit remote command code.
 * @return uint32_t LSB-first frame word with inverse bytes.
 */
static uint32_t nec_word(uint8_t command) {
    return 0x0000FF00u | ((uint32_t)command << 16u) |
           ((uint32_t)(uint8_t)~command << 24u);
}

/**
 * @brief Fill the thirty-two LSB-first mark and space durations.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param word LSB-first NEC frame word.
 * @return void
 */
static void nec_bits(uint16_t *pulses, uint32_t word) {
    uint8_t i;
    for (i = 0u; i < 32u; ++i) {
        pulses[2u + 2u * i] = 560u;
        pulses[3u + 2u * i] = ((word >> i) & 1u) ? 1690u : 560u;
    }
}

/**
 * @brief Fill a complete NEC pulse train for a command.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_fill(uint16_t *pulses, uint8_t command) {
    pulses[0] = 9000u;
    pulses[1] = 4500u;
    nec_bits(pulses, nec_word(command));
    pulses[66] = 560u;
    pulses[67] = 560u;
}

/**
 * @brief Append one NEC timeline point and advance the entry count.
 *
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @param n Current entry count.
 * @param at Absolute offset in microseconds.
 * @param level Level to record.
 * @return size_t Updated entry count.
 */
static size_t nec_append(uint32_t *offsets, int *levels, size_t n,
                         uint32_t at, int level) {
    offsets[n] = at;
    levels[n] = level;
    return n + 1u;
}

/**
 * @brief Lay a NEC pulse train onto a mock GPIO timeline.
 *
 * @param pulses Pointer to the pulse-duration buffer.
 * @param offsets Pointer to mutable offset array.
 * @param levels Pointer to mutable level array.
 * @return size_t Number of timeline entries written.
 */
static size_t nec_place(const uint16_t *pulses, uint32_t *offsets,
                        int *levels) {
    size_t i;
    size_t n = 0u;
    uint32_t t = 0u;
    for (i = 0u; i < IR_REMOTE_MAX_PULSES; ++i) {
        n = nec_append(offsets, levels, n, t, (i % 2u == 0u) ? 0 : 1);
        t += pulses[i];
    }
    n = nec_append(offsets, levels, n, t, 0);
    return n;
}

/**
 * @brief Arm the mock GPIO timeline with a NEC frame.
 *
 * @param command Eight-bit remote command code.
 * @return void
 */
static void nec_arm(uint8_t command) {
    size_t count;
    nec_fill(s_pulses, command);
    count = nec_place(s_pulses, s_ir_off, s_ir_lvl);
    mock_gpio_timeline_begin_at(mock_timer_now_us(), s_ir_off, s_ir_lvl,
                                count, ACCESS_GATE_IR_PIN);
}

/**
 * @brief Arm a full valid DHT11 interlock waveform at the current time.
 *
 * @param void No parameters.
 * @return void
 */
static void arm_climate(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    const uint8_t cold[SENSOR_BYTE_COUNT] = {50u, 0u, 0u, 0u, 0x32u};
    build_bits_from_bytes(cold, bits);
    mock_dht_timeline(bits, mock_timer_now_us());
}

/**
 * @brief Arm an out-of-band hot DHT11 interlock waveform.
 *
 * @param void No parameters.
 * @return void
 */
static void arm_bad_climate(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    const uint8_t hot[SENSOR_BYTE_COUNT] = {0u, 0u, 0x0Bu, 0u, 0x0Bu};
    build_bits_from_bytes(hot, bits);
    mock_dht_timeline(bits, mock_timer_now_us());
}

/**
 * @brief Write one 32-bit little-endian sequence into a buffer.
 *
 * @param body Pointer to the four-byte output.
 * @param seq Sequence value to serialize.
 * @return void
 */
static void put_seq(uint8_t *body, uint32_t seq) {
    body[0] = (uint8_t)(seq & 0xFFu);
    body[1] = (uint8_t)((seq >> 8u) & 0xFFu);
    body[2] = (uint8_t)((seq >> 16u) & 0xFFu);
    body[3] = (uint8_t)((seq >> 24u) & 0xFFu);
}

/**
 * @brief Build the signed body of a desk grant reply.
 *
 * @param seq Sequence number carried by the grant.
 * @param body Pointer to the MONITOR_REPLY_LEN output buffer.
 * @return bool true when the body was signed.
 */
static bool build_grant_body(uint32_t seq, uint8_t body[MONITOR_REPLY_LEN]) {
    gate_auth_t candidate;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    auth_candidate(seq, &candidate);
    if (!auth_state_tag(&candidate, tag)) {
        return false;
    }
    put_seq(body, seq);
    memcpy(body + 4u, tag, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Seal a desk grant reply into a hex envelope under the field key.
 *
 * @param seq Sequence number carried by the grant.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the grant was sealed.
 */
static bool seal_grant(uint32_t seq, char *hex, size_t hex_len) {
    uint8_t body[MONITOR_REPLY_LEN];
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)PACKET_NODE_ID;
    if (!build_grant_body(seq, body)) {
        return false;
    }
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(g_key, nonce, &ad, 1u, body, sizeof(body), hex,
                             hex_len);
}

/**
 * @brief Queue one sealed desk grant as an inbound +RCV line.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return void
 */
static void queue_reply(const char *hex) {
    char line[RADIO_LINE_BUF_LEN];
    snprintf(line, sizeof(line), "+RCV=0001,%u,%s,-40,5\r\n",
             (unsigned)strlen(hex), hex);
    mock_uart_set_rx(line, strlen(line));
}

/**
 * @brief Reset mocks and initialize a ready gate with a clean I2C log.
 *
 * @param void No parameters.
 * @return void
 */
static void init_gate(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    gpio_put(ACCESS_GATE_BUTTON_PIN, true);
    mock_i2c_reset();
}

/**
 * @brief Seal, queue, and apply a desk grant with a valid interlock.
 *
 * @param seq Sequence number carried by the grant.
 * @return bool true when the gate tick completed.
 */
static bool apply_grant_reply(uint32_t seq) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_grant(seq, hex, sizeof(hex))) {
        return false;
    }
    arm_climate();
    queue_reply(hex);
    return monitor_step();
}

/**
 * @brief Seal, queue, and apply a desk grant with no interlock waveform.
 *
 * @param seq Sequence number carried by the grant.
 * @return bool true when the gate tick completed.
 */
static bool apply_grant_reply_no_climate(uint32_t seq) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!seal_grant(seq, hex, sizeof(hex))) {
        return false;
    }
    queue_reply(hex);
    return monitor_step();
}

/**
 * @brief Assert that the green lamp is lit and the bolt is open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_granted(void) {
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(ACCESS_GATE_GREEN_LED_PIN));
    TEST_ASSERT_EQUAL_UINT(PACKET_SERVO_OPEN_PULSE_US,
                           mock_pwm_get_level(ACCESS_GATE_SERVO_PIN));
}

/**
 * @brief Assert that the red lamp is lit and the bolt is sealed.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_denied(void) {
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(ACCESS_GATE_RED_LED_PIN));
    TEST_ASSERT_EQUAL_UINT(PACKET_SERVO_LOCK_PULSE_US,
                           mock_pwm_get_level(ACCESS_GATE_SERVO_PIN));
}

/**
 * @brief Push a run of ascending digits onto the keypad.
 *
 * @param count Number of digits to push.
 * @return void
 */
static void push_digits(uint8_t count) {
    uint8_t i;
    for (i = 0u; i < count; ++i) {
        keypad_push_digit((uint8_t)(i % 10u));
    }
}

/**
 * @brief Press the request-to-exit button and clear its latch.
 *
 * @param void No parameters.
 * @return void
 */
static void press_rex(void) {
    rex_reset();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
}

/**
 * @brief Arm one NEC command and run a gate tick.
 *
 * @param command Eight-bit remote command code.
 * @return void
 */
static void send_ir(uint8_t command) {
    nec_arm(command);
    TEST_ASSERT_TRUE(monitor_step());
}

/**
 * @brief Enter a full ascending PIN and press ENTER over the infrared eye.
 *
 * @param void No parameters.
 * @return void
 */
static void send_pin(void) {
    uint8_t i;
    for (i = 0u; i < ACCESS_GATE_PIN_LENGTH; ++i) {
        send_ir(g_digit_commands[i]);
    }
    send_ir(MONITOR_IR_ENTER_COMMAND);
}

/**
 * @brief Build a signed state tag for a candidate grant sequence.
 *
 * @param seq Sequence number carried by the grant.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the tag was computed.
 */
static bool grant_tag(uint32_t seq, uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    gate_auth_t candidate;
    auth_candidate(seq, &candidate);
    return auth_state_tag(&candidate, tag);
}

/**
 * @brief Fill a candidate authorization record for a sequence.
 *
 * @param auth Pointer to the record to fill.
 * @param seq Sequence number to bind.
 * @return void
 */
static void fill_auth(gate_auth_t *auth, uint32_t seq) {
    auth_init(auth);
    auth->granted = true;
    auth->seq = seq;
    auth->last_seq = seq;
}

/**
 * @brief Compute and store the state tag for a record.
 *
 * @param auth Pointer to the record to sign.
 * @return void
 */
static void sign_auth(gate_auth_t *auth) {
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    TEST_ASSERT_TRUE(auth_state_tag(auth, tag));
    memcpy(auth->tag, tag, CRYPTO_AEAD_TAG_LEN);
}

void test_config_constants(void) {
    assert_pin_constants();
    assert_frame_constants();
    assert_band_constants();
}

void test_packet_artifact_constants(void) {
    assert_artifact_ids();
    assert_artifact_frame();
}

void test_crc16_ccitt(void) {
    TEST_ASSERT_EQUAL_HEX16(0xFFFFu,
                            crc16_ccitt((const uint8_t *)"", 0u));
    TEST_ASSERT_EQUAL_HEX16(0x29B1u,
                            crc16_ccitt((const uint8_t *)"123456789", 9u));
}

void test_dht_parse_bits_valid(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    fill_widths(bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_dht_parse_bits_checksum_fail(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    uint8_t i;
    for (i = 0u; i < SENSOR_BIT_COUNT; ++i) {
        bits[i] = s_widths[i];
    }
    bits[39] = 70u;
    TEST_ASSERT_FALSE(dht_parse_bits(bits, &r));
}

void test_dht_parse_bits_null(void) {
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    TEST_ASSERT_FALSE(dht_parse_bits(NULL, &r));
    TEST_ASSERT_FALSE(dht_parse_bits(bits, NULL));
}

void test_sensor_build_frame(void) {
    char frame[ACCESS_GATE_FRAME_SIZE];
    size_t n;
    load_reading();
    n = sensor_build_frame(&s_reading, 0u, frame, sizeof(frame));
    assert_frame_padding(frame, n, sizeof(frame));
    assert_frame_rejects(frame, sizeof(frame));
}

void test_sensor_climate_ok(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = 0;
    TEST_ASSERT_TRUE(sensor_climate_ok(&r));
    r.temperature_tenths = ACCESS_GATE_TEMP_MIN_TENTHS;
    TEST_ASSERT_TRUE(sensor_climate_ok(&r));
    r.temperature_tenths = ACCESS_GATE_TEMP_MAX_TENTHS;
    TEST_ASSERT_TRUE(sensor_climate_ok(&r));
}

void test_sensor_climate_rejects(void) {
    dht_reading_t r;
    r.valid = true;
    r.temperature_tenths = ACCESS_GATE_TEMP_MIN_TENTHS - 1;
    TEST_ASSERT_FALSE(sensor_climate_ok(&r));
    r.temperature_tenths = ACCESS_GATE_TEMP_MAX_TENTHS + 1;
    TEST_ASSERT_FALSE(sensor_climate_ok(&r));
    TEST_ASSERT_FALSE(sensor_climate_ok(NULL));
}

void test_sensor_climate_invalid(void) {
    dht_reading_t r;
    r.valid = false;
    r.temperature_tenths = 0;
    TEST_ASSERT_FALSE(sensor_climate_ok(&r));
}

void test_sensor_read_dht_waveform(void) {
    sensor_init();
    mock_dht_timeline(s_widths, 0u);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_OK, sensor_read(&s_reading));
    TEST_ASSERT_TRUE(s_reading.valid);
    TEST_ASSERT_EQUAL_INT(230, s_reading.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(610u, s_reading.humidity_tenths);
}

void test_sensor_read_timeout(void) {
    dht_reading_t r;
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_radio_build_send_cmd(void) {
    char cmd[64];
    radio_result_t rc;
    rc = radio_build_send_cmd(0x0001u, (const uint8_t *)"abc", 3u, cmd,
                              sizeof(cmd));
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_EQUAL_STRING("AT+SEND=0001,3,abc\r\n", cmd);
    assert_build_rejects(cmd, sizeof(cmd));
}

void test_radio_parse_rcv(void) {
    assert_rcv_json();
    assert_rcv_comma();
    assert_rcv_no_tail();
}

void test_radio_parse_rcv_rejects(void) {
    assert_rcv_rejects();
}

void test_radio_line_pump(void) {
    char line[32];
    size_t len = 0u;
    mock_uart_reset();
    mock_uart_set_rx("ab\r\ncd\r\n", 8u);
    assert_pump_lines(line, &len);
}

void test_radio_spoofed_sender_attribution(void) {
    radio_rcv_t rcv;
    radio_result_t rc;
    rc = radio_parse_rcv("+RCV=0007,7,{\"a\",1},-90,3", &rcv);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK, rc);
    TEST_ASSERT_TRUE(radio_frame_is_from(&rcv, 0x0007u));
    TEST_ASSERT_FALSE(radio_frame_is_from(&rcv, 0x0008u));
}

void test_display_format_lines(void) {
    assert_format_ok();
    assert_format_fail();
}

void test_display_render_lines(void) {
    load_display_lines();
    mock_i2c_reset();
    display_render_lines(i2c1, ACCESS_GATE_LCD_ADDR, s_line1, s_line2);
    assert_lcd_frame("T:23.0C H:61.0%", "N:07 S:0042 OK");
}

void test_keypad_accumulate(void) {
    char pin[ACCESS_GATE_PIN_LENGTH + 1u];
    keypad_reset();
    push_digits(ACCESS_GATE_PIN_LENGTH);
    TEST_ASSERT_TRUE(keypad_enter());
    TEST_ASSERT_TRUE(keypad_pin_ready());
    TEST_ASSERT_TRUE(keypad_get_pin(pin, sizeof(pin)));
    TEST_ASSERT_EQUAL_STRING("012345", pin);
    TEST_ASSERT_FALSE(keypad_pin_ready());
}

void test_keypad_overflow(void) {
    keypad_reset();
    TEST_ASSERT_FALSE(keypad_enter());
    push_digits(ACCESS_GATE_PIN_LENGTH);
    TEST_ASSERT_FALSE(keypad_push_digit(9u));
    TEST_ASSERT_FALSE(keypad_push_digit(10u));
    TEST_ASSERT_EQUAL_UINT8(ACCESS_GATE_PIN_LENGTH, g_keypad_count);
}

void test_keypad_clear(void) {
    keypad_reset();
    push_digits(3u);
    keypad_clear();
    TEST_ASSERT_EQUAL_UINT8(0u, g_keypad_count);
    TEST_ASSERT_FALSE(keypad_pin_ready());
}

void test_keypad_get_guards(void) {
    char small[4];
    char pin[ACCESS_GATE_PIN_LENGTH + 1u];
    keypad_reset();
    TEST_ASSERT_FALSE(keypad_get_pin(pin, sizeof(pin)));
    push_digits(ACCESS_GATE_PIN_LENGTH);
    keypad_enter();
    TEST_ASSERT_FALSE(keypad_get_pin(NULL, sizeof(pin)));
    TEST_ASSERT_FALSE(keypad_get_pin(small, sizeof(small)));
}

void test_auth_state_tag(void) {
    gate_auth_t auth;
    auth_set_key(s_key);
    fill_auth(&auth, 3u);
    sign_auth(&auth);
    TEST_ASSERT_TRUE(auth_state_ok(&auth));
    auth.granted = false;
    TEST_ASSERT_FALSE(auth_state_ok(&auth));
}

void test_auth_apply_window(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    auth_set_key(s_key);
    auth_init(&auth);
    TEST_ASSERT_TRUE(grant_tag(1u, tag));
    TEST_ASSERT_TRUE(auth_apply_grant(&auth, 1u, tag));
    TEST_ASSERT_FALSE(auth_apply_grant(&auth, 1u, tag));
    TEST_ASSERT_FALSE(auth_apply_grant(&auth, 0u, tag));
}

void test_auth_apply_advance(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    auth_set_key(s_key);
    auth_init(&auth);
    TEST_ASSERT_TRUE(grant_tag(2u, tag));
    TEST_ASSERT_TRUE(auth_apply_grant(&auth, 2u, tag));
    TEST_ASSERT_EQUAL_UINT(2u, auth.last_seq);
}

void test_auth_apply_bad_tag(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    auth_set_key(s_key);
    auth_init(&auth);
    TEST_ASSERT_FALSE(auth_apply_grant(&auth, 5u, tag));
}

void test_auth_null_guards(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    auth_init(&auth);
    TEST_ASSERT_FALSE(auth_apply_grant(NULL, 1u, tag));
    TEST_ASSERT_FALSE(auth_apply_grant(&auth, 1u, NULL));
    TEST_ASSERT_FALSE(auth_state_tag(&auth, NULL));
    auth_init(NULL);
}

void test_auth_state_guards(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN] = {0u};
    auth_init(&auth);
    auth_set_key(NULL);
    TEST_ASSERT_FALSE(auth_state_tag(&auth, tag));
    TEST_ASSERT_FALSE(auth_state_ok(&auth));
    TEST_ASSERT_FALSE(auth_apply_grant(&auth, 1u, tag));
}

void test_auth_tag_guard(void) {
    gate_auth_t auth;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    auth_set_key(s_key);
    auth_init(&auth);
    TEST_ASSERT_FALSE(auth_state_tag(NULL, tag));
}

void test_auth_begin_request(void) {
    gate_auth_t auth;
    auth_init(&auth);
    auth.granted = true;
    auth_begin_request(&auth);
    TEST_ASSERT_TRUE(auth.pending);
    TEST_ASSERT_FALSE(auth.granted);
    auth_begin_request(NULL);
}

void test_monitor_init(void) {
    reset_all();
    TEST_ASSERT_TRUE(monitor_init());
    TEST_ASSERT_EQUAL_UINT(115200u, s_mock_uart_baud);
    TEST_ASSERT_TRUE(s_mock_gpio_dirs[ACCESS_GATE_LED_PIN]);
    TEST_ASSERT(mock_i2c_log_count() > 0u);
}

void test_monitor_init_lcd_fail(void) {
    reset_all();
    mock_i2c_set_write_fail(true);
    TEST_ASSERT_FALSE(monitor_init());
}

void test_monitor_not_ready(void) {
    reset_all();
    monitor_deinit();
    TEST_ASSERT_FALSE(monitor_step());
}

void test_monitor_step_idle(void) {
    init_gate();
    TEST_ASSERT_TRUE(monitor_step());
    assert_lcd_frame("PIN: S:0000", "STATE:OFF");
}

void test_monitor_heartbeat(void) {
    init_gate();
    g_heartbeat_ticks = 0u;
    g_heartbeat_level = false;
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(ACCESS_GATE_LED_PIN));
}

void test_monitor_render_log(void) {
    init_gate();
    snprintf(g_last_pin, sizeof(g_last_pin), "%s", "4821");
    g_auth.last_seq = 7u;
    g_state = STATUS_LED_GRANTED;
    mock_i2c_reset();
    monitor_render();
    assert_lcd_frame("PIN:4821 S:0007", "STATE:GRANTED");
}

void test_monitor_state_text(void) {
    TEST_ASSERT_EQUAL_STRING("OFF", monitor_state_text(STATUS_LED_OFF));
    TEST_ASSERT_EQUAL_STRING("DENIED", monitor_state_text(STATUS_LED_DENIED));
    TEST_ASSERT_EQUAL_STRING("PENDING", monitor_state_text(STATUS_LED_PENDING));
    TEST_ASSERT_EQUAL_STRING("GRANTED", monitor_state_text(STATUS_LED_GRANTED));
}

void test_monitor_interlock_direct(void) {
    init_gate();
    arm_climate();
    TEST_ASSERT_TRUE(monitor_interlock_ok());
    arm_bad_climate();
    TEST_ASSERT_FALSE(monitor_interlock_ok());
    TEST_ASSERT_FALSE(monitor_interlock_ok());
}

void test_monitor_grant_success(void) {
    init_gate();
    TEST_ASSERT_TRUE(apply_grant_reply(1u));
    assert_granted();
    TEST_ASSERT_EQUAL_UINT(1u, g_auth.last_seq);
}

void test_monitor_grant_replay(void) {
    init_gate();
    TEST_ASSERT_TRUE(apply_grant_reply(1u));
    assert_granted();
    TEST_ASSERT_TRUE(apply_grant_reply(1u));
    assert_denied();
}

void test_monitor_grant_bad_tag(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    init_gate();
    TEST_ASSERT_TRUE(seal_grant(1u, hex, sizeof(hex)));
    hex[40] = (hex[40] == '0') ? '1' : '0';
    arm_climate();
    queue_reply(hex);
    TEST_ASSERT_TRUE(monitor_step());
    assert_denied();
}

void test_monitor_grant_interlock_fail(void) {
    init_gate();
    TEST_ASSERT_TRUE(apply_grant_reply_no_climate(1u));
    assert_denied();
}

void test_monitor_state_tag_tamper(void) {
    init_gate();
    auth_begin_request(&g_auth);
    g_auth.granted = true;
    monitor_grant_release();
    assert_denied();
}

void test_monitor_rex_unlock(void) {
    init_gate();
    arm_climate();
    press_rex();
    TEST_ASSERT_TRUE(monitor_step());
    assert_granted();
}

void test_monitor_rex_climate_block(void) {
    init_gate();
    arm_bad_climate();
    press_rex();
    TEST_ASSERT_TRUE(monitor_step());
    assert_denied();
}

void test_monitor_hold_expiry(void) {
    init_gate();
    TEST_ASSERT_TRUE(apply_grant_reply(1u));
    assert_granted();
    mock_timer_set_us(mock_timer_now_us() +
                      (uint64_t)MONITOR_HOLD_MS * 1000u + 1u);
    TEST_ASSERT_TRUE(monitor_step());
    TEST_ASSERT_EQUAL_INT(0, mock_gpio_get(ACCESS_GATE_GREEN_LED_PIN));
}

void test_monitor_pending_expiry(void) {
    init_gate();
    monitor_send_request("4821");
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(ACCESS_GATE_YELLOW_LED_PIN));
    mock_timer_set_us(mock_timer_now_us() +
                      (uint64_t)ACCESS_GATE_AUTH_WAIT_MS * 1000u + 1u);
    TEST_ASSERT_TRUE(monitor_step());
    assert_denied();
}

void test_monitor_pending_fail_open(void) {
    init_gate();
    monitor_send_request("4821");
    g_fail_secure = false;
    mock_timer_set_us(mock_timer_now_us() +
                      (uint64_t)ACCESS_GATE_AUTH_WAIT_MS * 1000u + 1u);
    TEST_ASSERT_TRUE(monitor_step());
    assert_granted();
    g_fail_secure = true;
}

void test_monitor_send_request_no_key(void) {
    init_gate();
    g_key_ready = false;
    monitor_send_request("4821");
    assert_denied();
    g_key_ready = true;
}

void test_monitor_open_reply_guards(void) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    init_gate();
    g_key_ready = false;
    TEST_ASSERT_FALSE(monitor_open_reply("00", &seq, tag));
    g_key_ready = true;
    TEST_ASSERT_FALSE(monitor_open_reply("00", &seq, tag));
}

void test_monitor_parse_reply_guards(void) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    uint8_t body[MONITOR_REPLY_LEN] = {1u};
    TEST_ASSERT_FALSE(monitor_parse_reply(NULL, MONITOR_REPLY_LEN, &seq, tag));
    TEST_ASSERT_FALSE(monitor_parse_reply(body, 4u, &seq, tag));
    TEST_ASSERT_FALSE(monitor_parse_reply(body, MONITOR_REPLY_LEN, NULL, tag));
    TEST_ASSERT_TRUE(monitor_parse_reply(body, MONITOR_REPLY_LEN, &seq, tag));
    TEST_ASSERT_EQUAL_UINT(1u, seq);
}

void test_monitor_digit_command(void) {
    keypad_reset();
    TEST_ASSERT_EQUAL_INT(7, monitor_digit_command(MONITOR_IR_DIGIT_7));
    TEST_ASSERT_EQUAL_INT(-1, monitor_digit_command(0x20u));
    monitor_apply_digit(3);
    monitor_apply_digit(-1);
    TEST_ASSERT_EQUAL_UINT8(1u, g_keypad_count);
    TEST_ASSERT_EQUAL_UINT8(3u, g_keypad_digits[0]);
}

void test_monitor_apply_ir_branches(void) {
    ir_command_t cmd;
    keypad_reset();
    monitor_handle_enter();
    cmd.command = MONITOR_IR_DIGIT_5;
    monitor_apply_ir(&cmd);
    cmd.command = MONITOR_IR_CLEAR_COMMAND;
    monitor_apply_ir(&cmd);
    TEST_ASSERT_EQUAL_UINT8(0u, g_keypad_count);
}

void test_monitor_apply_ir_enter(void) {
    ir_command_t cmd;
    init_gate();
    push_digits(ACCESS_GATE_PIN_LENGTH);
    cmd.command = MONITOR_IR_ENTER_COMMAND;
    monitor_apply_ir(&cmd);
    TEST_ASSERT_EQUAL_STRING("012345", g_last_pin);
}

void test_monitor_ir_request(void) {
    init_gate();
    send_pin();
    TEST_ASSERT_EQUAL_STRING("012345", g_last_pin);
    TEST_ASSERT_EQUAL_INT(1, mock_gpio_get(ACCESS_GATE_YELLOW_LED_PIN));
}

void test_sensor_policy_not_ready(void) {
    dht_reading_t r;
    sensor_deinit();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(&r));
}

void test_sensor_policy_null_out(void) {
    sensor_init();
    TEST_ASSERT_EQUAL(SENSOR_RESULT_POLICY_ERROR, sensor_read(NULL));
}

void test_sensor_dht_negative_temp(void) {
    const uint8_t bytes[SENSOR_BYTE_COUNT] = {0u, 0u, 0x82u, 3u, 0x85u};
    uint16_t bits[SENSOR_BIT_COUNT];
    dht_reading_t r;
    build_bits_from_bytes(bytes, bits);
    TEST_ASSERT_TRUE(dht_parse_bits(bits, &r));
    TEST_ASSERT_TRUE(r.valid);
    TEST_ASSERT_EQUAL_INT(-17, r.temperature_tenths);
    TEST_ASSERT_EQUAL_UINT(0u, r.humidity_tenths);
}

void test_sensor_read_timeout_response_low(void) {
    uint32_t offsets[4] = {0u, 30u};
    int levels[4] = {1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 2u, ACCESS_GATE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_response_high(void) {
    uint32_t offsets[4] = {0u, 30u, 110u};
    int levels[4] = {1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 3u, ACCESS_GATE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_timeout_bit_low(void) {
    uint32_t offsets[4] = {0u, 30u, 110u, 190u};
    int levels[4] = {1, 0, 1, 0};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 4u, ACCESS_GATE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_sensor_read_measure_timeout(void) {
    uint32_t offsets[8] = {0u, 30u, 110u, 190u, 240u};
    int levels[8] = {1, 0, 1, 0, 1};
    dht_reading_t r;
    sensor_init();
    mock_gpio_timeline_begin_at(0u, offsets, levels, 5u, ACCESS_GATE_DHT_PIN);
    TEST_ASSERT_EQUAL(SENSOR_RESULT_TIMEOUT, sensor_read(&r));
}

void test_radio_hex_digits(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00a7,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00A7u, rcv.sender);
    TEST_ASSERT_EQUAL(RADIO_RESULT_OK,
                      radio_parse_rcv("+RCV=00FE,2,ok,-3,2", &rcv));
    TEST_ASSERT_EQUAL_HEX16(0x00FEu, rcv.sender);
}

void test_radio_build_send_cmd_oversize_cmd(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    char tiny[16];
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_build_send_cmd(0x0001u, payload, 29u, tiny,
                                           sizeof(tiny)));
}

void test_radio_send_frame_oversize(void) {
    const uint8_t payload[30] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";
    TEST_ASSERT_EQUAL(RADIO_RESULT_OVERSIZE,
                      radio_send_frame(uart0, payload, 257u));
}

void test_radio_parse_missing_commas(void) {
    radio_rcv_t rcv;
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=007ZX,3,hi,-1,1", &rcv));
    TEST_ASSERT_EQUAL(RADIO_RESULT_PARSE_ERROR,
                      radio_parse_rcv("+RCV=0007,9Z,hi,-1,1", &rcv));
}

void setUp(void) {
    reset_all();
}

void tearDown(void) {
}

/**
 * @brief Run the provisioning, artifact, and display tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_basic_tests(void) {
    RUN_TEST(test_config_constants);
    RUN_TEST(test_packet_artifact_constants);
    RUN_TEST(test_crc16_ccitt);
    RUN_TEST(test_display_format_lines);
    RUN_TEST(test_display_render_lines);
}

/**
 * @brief Run the sensor sampling and interlock tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_sensor_tests(void) {
    RUN_TEST(test_dht_parse_bits_valid);
    RUN_TEST(test_dht_parse_bits_checksum_fail);
    RUN_TEST(test_dht_parse_bits_null);
    RUN_TEST(test_sensor_build_frame);
    RUN_TEST(test_sensor_climate_ok);
    RUN_TEST(test_sensor_climate_rejects);
    RUN_TEST(test_sensor_climate_invalid);
    RUN_TEST(test_sensor_read_dht_waveform);
}

/**
 * @brief Run the sensor timeout and policy tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_policy_tests(void) {
    RUN_TEST(test_sensor_read_timeout);
    RUN_TEST(test_sensor_policy_not_ready);
    RUN_TEST(test_sensor_policy_null_out);
    RUN_TEST(test_sensor_dht_negative_temp);
    RUN_TEST(test_sensor_read_timeout_response_low);
    RUN_TEST(test_sensor_read_timeout_response_high);
    RUN_TEST(test_sensor_read_timeout_bit_low);
    RUN_TEST(test_sensor_read_measure_timeout);
}

/**
 * @brief Run the radio protocol tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_tests(void) {
    RUN_TEST(test_radio_build_send_cmd);
    RUN_TEST(test_radio_parse_rcv);
    RUN_TEST(test_radio_parse_rcv_rejects);
    RUN_TEST(test_radio_line_pump);
    RUN_TEST(test_radio_spoofed_sender_attribution);
}

/**
 * @brief Run the radio edge-case tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_radio_edge_tests(void) {
    RUN_TEST(test_radio_hex_digits);
    RUN_TEST(test_radio_build_send_cmd_oversize_cmd);
    RUN_TEST(test_radio_send_frame_oversize);
    RUN_TEST(test_radio_parse_missing_commas);
}

/**
 * @brief Run the keypad accumulator tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_keypad_tests(void) {
    RUN_TEST(test_keypad_accumulate);
    RUN_TEST(test_keypad_overflow);
    RUN_TEST(test_keypad_clear);
    RUN_TEST(test_keypad_get_guards);
}

/**
 * @brief Run the authorization record tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_auth_tests(void) {
    RUN_TEST(test_auth_state_tag);
    RUN_TEST(test_auth_apply_window);
    RUN_TEST(test_auth_apply_advance);
    RUN_TEST(test_auth_apply_bad_tag);
    RUN_TEST(test_auth_null_guards);
    RUN_TEST(test_auth_state_guards);
    RUN_TEST(test_auth_tag_guard);
    RUN_TEST(test_auth_begin_request);
}

/**
 * @brief Run the gate state-machine tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_monitor_tests(void) {
    RUN_TEST(test_monitor_init);
    RUN_TEST(test_monitor_init_lcd_fail);
    RUN_TEST(test_monitor_not_ready);
    RUN_TEST(test_monitor_step_idle);
    RUN_TEST(test_monitor_heartbeat);
    RUN_TEST(test_monitor_render_log);
    RUN_TEST(test_monitor_state_text);
    RUN_TEST(test_monitor_interlock_direct);
}


/**
 * @brief Run the deadbolt authorization and egress tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_deadbolt_tests(void) {
    RUN_TEST(test_monitor_grant_success);
    RUN_TEST(test_monitor_grant_replay);
    RUN_TEST(test_monitor_grant_bad_tag);
    RUN_TEST(test_monitor_grant_interlock_fail);
    RUN_TEST(test_monitor_state_tag_tamper);
    RUN_TEST(test_monitor_rex_unlock);
    RUN_TEST(test_monitor_rex_climate_block);
    RUN_TEST(test_monitor_hold_expiry);
}

/**
 * @brief Run the request, expiry, and infrared dispatch tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_request_tests(void) {
    RUN_TEST(test_monitor_pending_expiry);
    RUN_TEST(test_monitor_send_request_no_key);
    RUN_TEST(test_monitor_open_reply_guards);
    RUN_TEST(test_monitor_parse_reply_guards);
    RUN_TEST(test_monitor_apply_ir_branches);
    RUN_TEST(test_monitor_apply_ir_enter);
    RUN_TEST(test_monitor_ir_request);
    RUN_TEST(test_monitor_digit_command);
}

/**
 * @brief Run the fail-mode policy test group.
 *
 * @param void No parameters.
 * @return void
 */
static void run_fail_mode_tests(void) {
    RUN_TEST(test_monitor_pending_fail_open);
}

/**
 * @brief Run the peripheral and security module test groups.
 *
 * @param void No parameters.
 * @return void
 */
extern void run_peripheral_and_crypto_tests(void);

/**
 * @brief Run the provisioning, sensor, radio, keypad, and auth tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_unit_tests(void) {
    run_basic_tests();
    run_sensor_tests();
    run_policy_tests();
    run_radio_tests();
    run_radio_edge_tests();
    run_keypad_tests();
    run_auth_tests();
}

/**
 * @brief Run every owned access-gate test group.
 *
 * @param void No parameters.
 * @return void
 */
static void run_own_tests(void) {
    run_unit_tests();
    run_monitor_tests();
    run_deadbolt_tests();
    run_request_tests();
    run_fail_mode_tests();
}

int main(void) {
    TEST_BEGIN();
    run_own_tests();
    run_peripheral_and_crypto_tests();
    return TEST_END();
}
