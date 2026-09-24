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
// File:    monitor.c
// Desc:    Implements the access-gate state machine that ties the infrared
//          keypad, the authorization record, the deadbolt, the DHT11
//          interlock, and the RYLR998 security-desk link together.
// Created: 2026

#include "access_gate.h"
#include "monitor.h"
#include "sensor.h"
#include "display.h"
#include "radio.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "keypad.h"
#include "auth.h"
#include "crypto_aead.h"
#include "crypto_kdf.h"
#include "envelope.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "hardware/uart.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Module-ready flag.
 *
 * Set to true by monitor_init() once all peripherals are configured.
 * monitor_step() returns false while this flag is clear.
 */
static bool g_ready;

/**
 * @brief Initialized I2C peripheral handle for the LCD backpack.
 */
static i2c_inst_t *g_i2c;

/**
 * @brief Initialized I2C backpack address for the LCD.
 */
static uint8_t g_i2c_addr;

/**
 * @brief Derived XChaCha20-Poly1305 field key for the security desk link.
 */
static uint8_t g_key[CRYPTO_AEAD_KEY_LEN];

/**
 * @brief True once the field key has been derived and installed.
 */
static bool g_key_ready;

/**
 * @brief Authorization record with its anti-replay window and state tag.
 */
static gate_auth_t g_auth;

/**
 * @brief Fail mode policy: true seals the bolt when authorization times out.
 */
static volatile bool g_fail_secure = true;

/**
 * @brief Current gate annunciator and policy state.
 */
static status_led_state_t g_state;

/**
 * @brief Last observed environmental interlock verdict.
 */
static bool g_climate_ok;

/**
 * @brief Absolute time in microseconds when the grant hold expires.
 */
static uint64_t g_hold_until_us;

/**
 * @brief Absolute time in microseconds when the pending wait expires.
 */
static uint64_t g_pending_until_us;

/**
 * @brief First LCD access-log render line buffer.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second LCD access-log render line buffer.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief Most recent badge PIN rendered in the access log.
 */
static char g_last_pin[ACCESS_GATE_PIN_LENGTH + 1u];

/**
 * @brief Count of monitor ticks since the last onboard heartbeat toggle.
 */
static uint32_t g_heartbeat_ticks;

/**
 * @brief Current onboard heartbeat LED level.
 */
static bool g_heartbeat_level;

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(ACCESS_GATE_I2C, ACCESS_GATE_I2C_BAUD);
    gpio_set_function(ACCESS_GATE_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(ACCESS_GATE_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(ACCESS_GATE_I2C_SDA);
    gpio_pull_up(ACCESS_GATE_I2C_SCL);
    i2c_bus_scan(ACCESS_GATE_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_gpio_init(void) {
    gpio_init(ACCESS_GATE_LED_PIN);
    gpio_set_dir(ACCESS_GATE_LED_PIN, GPIO_OUT);
    gpio_put(ACCESS_GATE_LED_PIN, 0);
}

/**
 * @brief Toggle the onboard GP25 heartbeat LED on its interval.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    g_heartbeat_ticks += 1u;
    if (g_heartbeat_ticks < MONITOR_HEARTBEAT_TICKS) {
        return;
    }
    g_heartbeat_ticks = 0u;
    g_heartbeat_level = !g_heartbeat_level;
    gpio_put(ACCESS_GATE_LED_PIN, g_heartbeat_level);
}

/**
 * @brief Initialize the LED, LCD handles, and authorization record.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    monitor_gpio_init();
    g_i2c = ACCESS_GATE_I2C;
    g_i2c_addr = ACCESS_GATE_LCD_ADDR;
    g_state = STATUS_LED_OFF;
    auth_init(&g_auth);
    g_ready = true;
}

/**
 * @brief Initialize the human interface and actuator peripherals.
 *
 * @param void No parameters.
 * @return bool true when the LEDs, REX, servo, and infrared eye ready.
 */
static bool monitor_peripherals_init(void) {
    return status_led_init() && rex_init() && servo_init() &&
           ir_remote_init();
}

/**
 * @brief Derive the field key from the committed lab secret.
 *
 * LAB-ONLY: production must provision the field key through OTP rather
 * than deriving it from a committed passphrase and salt.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_derive_key(void) {
    bool ok = crypto_kdf_argon2id((const uint8_t *)FIELD_SECRET_PASSPHRASE, strlen(FIELD_SECRET_PASSPHRASE), FIELD_SECRET_SALT, 16u, g_key);
    g_key_ready = ok;
    auth_set_key(ok ? g_key : NULL);
    return ok;
}

/**
 * @brief Print the boot banner and the interactive control hint.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_banner(void) {
    printf("=== OPERATION IRON GATE // ACT II ACCESS CONTROL ===\n");
    printf("REMOTE: CH+ 0x47 spare | CH- 0x45 clear | CH 0x46 enter\n");
    printf("KEYPAD: 0x16-0x4A digits | BUTTON: GP15 request-to-exit\n");
}

/**
 * @brief Derive the field key and announce a ready gate.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_finish(void) {
    bool ok = monitor_derive_key();
    if (ok) {
        monitor_banner();
    }
    return ok;
}

bool monitor_init(void) {
    monitor_bus_init();
    if (!monitor_peripherals_init() || !sensor_init() ||
        !radio_init(ACCESS_GATE_UART) ||
        !display_init(ACCESS_GATE_I2C, ACCESS_GATE_LCD_ADDR)) {
        printf("INIT FAIL\n");
        return false;
    }
    monitor_state_init();
    return monitor_finish();
}

void monitor_deinit(void) {
    g_ready = false;
}

/**
 * @brief Update the gate state and drive the annunciator.
 *
 * @param state Desired annunciator state.
 * @return void
 */
static void monitor_show(status_led_state_t state) {
    g_state = state;
    status_led_show(state);
}

/**
 * @brief Seal the deadbolt and annunciate a state.
 *
 * @param state Desired annunciator state.
 * @return void
 */
static void monitor_lock(status_led_state_t state) {
    servo_lock();
    monitor_show(state);
}

/**
 * @brief Open the deadbolt for a bounded hold.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_release(void) {
    servo_unlock();
    monitor_show(STATUS_LED_GRANTED);
    g_hold_until_us = time_us_64() + (uint64_t)MONITOR_HOLD_MS * 1000u;
}

/**
 * @brief Render a gate state as a short access-log label.
 *
 * @param state Gate state to render.
 * @return const char* NUL-terminated state label.
 */
static const char *monitor_state_text(status_led_state_t state) {
    if (state == STATUS_LED_DENIED) return "DENIED";
    if (state == STATUS_LED_PENDING) return "PENDING";
    if (state == STATUS_LED_GRANTED) return "GRANTED";
    return "OFF";
}

/**
 * @brief Print one live status line for the interactive console.
 *
 * @param reading Pointer to the decoded DHT11 interlock reading.
 * @return void
 */
static void monitor_log_reading(const dht_reading_t *reading) {
    printf("INTERLOCK t=%d h=%u valid=%d LED=%s seq=%u\n",
           (int)reading->temperature_tenths, (unsigned)reading->humidity_tenths,
           (int)reading->valid, monitor_state_text(g_state),
           (unsigned)g_auth.last_seq);
}

/**
 * @brief Render the access log to the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    snprintf(g_line1, DISPLAY_LINE_LEN, "PIN:%s S:%04u", g_last_pin,
             (unsigned)g_auth.last_seq);
    snprintf(g_line2, DISPLAY_LINE_LEN, "STATE:%s",
             monitor_state_text(g_state));
    display_render_lines(g_i2c, g_i2c_addr, g_line1, g_line2);
}

/**
 * @brief Sample the DHT11 vault interlock.
 *
 * @param void No parameters.
 * @return bool true when the reading is valid and inside the safe band.
 */
static bool monitor_interlock_ok(void) {
    dht_reading_t reading;
    if (sensor_read(&reading) != SENSOR_RESULT_OK) {
        g_climate_ok = false;
        printf("SENSOR read failed -> WARNING\n");
        return false;
    }
    g_climate_ok = sensor_climate_ok(&reading);
    monitor_log_reading(&reading);
    return g_climate_ok;
}

/**
 * @brief Release the deadbolt only when the state tag and interlock pass.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_grant_release(void) {
    if (!auth_state_ok(&g_auth)) {
        monitor_lock(STATUS_LED_DENIED);
        return;
    }
    if (!monitor_interlock_ok()) {
        monitor_lock(STATUS_LED_DENIED);
        return;
    }
    monitor_release();
}

/**
 * @brief Decode a desk reply body into a sequence and a state tag.
 *
 * @param pt Pointer to the recovered reply plaintext.
 * @param len Number of recovered plaintext bytes.
 * @param seq Pointer to store the little-endian sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the reply body was long enough.
 */
static bool monitor_parse_reply(const uint8_t *pt, size_t len, uint32_t *seq,
                                uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    if (pt == NULL || seq == NULL || len < MONITOR_REPLY_LEN) {
        return false;
    }
    *seq = (uint32_t)pt[0] | ((uint32_t)pt[1] << 8u) |
           ((uint32_t)pt[2] << 16u) | ((uint32_t)pt[3] << 24u);
    memcpy(tag, pt + 4u, CRYPTO_AEAD_TAG_LEN);
    return true;
}

/**
 * @brief Open and decode a sealed desk grant reply.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @param seq Pointer to store the recovered sequence number.
 * @param tag Pointer to the 16-byte tag output buffer.
 * @return bool true when the reply authenticated and decoded.
 */
static bool monitor_open_reply(const char *hex, uint32_t *seq,
                               uint8_t tag[CRYPTO_AEAD_TAG_LEN]) {
    uint8_t pt[ENVELOPE_MAX_PLAINTEXT];
    uint8_t ad = (uint8_t)PACKET_NODE_ID;
    size_t pt_len;
    if (!g_key_ready) return false;
    if (!envelope_open_hex(g_key, &ad, 1u, hex, pt, sizeof(pt), &pt_len)) return false;
    return monitor_parse_reply(pt, pt_len, seq, tag);
}

/**
 * @brief Verify a desk grant against the anti-replay window and state tag.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return bool true when the grant was accepted.
 */
static bool monitor_verify_grant(const char *hex) {
    uint32_t seq;
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    if (!monitor_open_reply(hex, &seq, tag)) {
        return false;
    }
    return auth_apply_grant(&g_auth, seq, tag);
}

/**
 * @brief Apply an authenticated desk reply to the deadbolt.
 *
 * @param hex Pointer to the NUL-terminated hex envelope.
 * @return void
 */
static void monitor_apply_reply(const char *hex) {
    if (!monitor_verify_grant(hex)) {
        monitor_lock(STATUS_LED_DENIED);
        return;
    }
    monitor_grant_release();
}

/**
 * @brief Drain inbound radio lines and apply any desk grant.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_rx_tick(void) {
    radio_rcv_t rcv;
    while (radio_line_pump(ACCESS_GATE_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender,
                   (unsigned)rcv.len);
            monitor_apply_reply(rcv.payload);
        }
    }
}

/**
 * @brief Consume one debounced request-to-exit press.
 *
 * This is the deliberate, unauthenticated life-safety egress path: a
 * person inside the vault can always leave without a desk grant.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_rex(void) {
    if (!rex_consume_press()) {
        return;
    }
    printf("BUTTON request-to-exit -> release check\n");
    if (!monitor_interlock_ok()) {
        monitor_lock(STATUS_LED_DENIED);
        return;
    }
    monitor_release();
}

/**
 * @brief Infrared digit command codes indexed by decimal digit value.
 */
static const uint8_t g_digit_commands[10] = {
    MONITOR_IR_DIGIT_0, MONITOR_IR_DIGIT_1, MONITOR_IR_DIGIT_2,
    MONITOR_IR_DIGIT_3, MONITOR_IR_DIGIT_4, MONITOR_IR_DIGIT_5,
    MONITOR_IR_DIGIT_6, MONITOR_IR_DIGIT_7, MONITOR_IR_DIGIT_8,
    MONITOR_IR_DIGIT_9,
};

/**
 * @brief Map an infrared command code to a decimal digit.
 *
 * @param command Eight-bit remote command code.
 * @return int Digit value, or -1 when the command is not a digit.
 */
static int monitor_digit_command(uint8_t command) {
    uint8_t digit;
    for (digit = 0u; digit < 10u; ++digit) {
        if (g_digit_commands[digit] == command) {
            return (int)digit;
        }
    }
    return -1;
}

/**
 * @brief Push a decoded digit onto the keypad accumulator.
 *
 * @param digit Digit value, or -1 when the command was not a digit.
 * @return void
 */
static void monitor_apply_digit(int digit) {
    if (digit >= 0) {
        keypad_push_digit((uint8_t)digit);
    }
}

/**
 * @brief Seal the entered PIN into a hex request envelope.
 *
 * @param pin Pointer to the NUL-terminated PIN text.
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the PIN was sealed and encoded.
 */
static bool monitor_seal_request(const char *pin, char *hex, size_t hex_len) {
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)PACKET_NODE_ID;
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(g_key, nonce, &ad, 1u, (const uint8_t *)pin,
                             strlen(pin), hex, hex_len);
}

/**
 * @brief Send a sealed unlock request to the security desk.
 *
 * @param pin Pointer to the NUL-terminated PIN text.
 * @return void
 */
static void monitor_send_request(const char *pin) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    snprintf(g_last_pin, sizeof(g_last_pin), "%s", pin);
    if (!g_key_ready || !monitor_seal_request(pin, hex, sizeof(hex))) {
        monitor_lock(STATUS_LED_DENIED);
        return;
    }
    radio_send_frame(ACCESS_GATE_UART, (const uint8_t *)hex, strlen(hex));
    monitor_show(STATUS_LED_PENDING);
    g_pending_until_us = time_us_64() + (uint64_t)ACCESS_GATE_AUTH_WAIT_MS * 1000u;
}

/**
 * @brief Consume a latched PIN and begin an authorization request.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_enter(void) {
    char pin[ACCESS_GATE_PIN_LENGTH + 1u];
    if (!keypad_enter() || !keypad_get_pin(pin, sizeof(pin))) {
        return;
    }
    auth_begin_request(&g_auth);
    monitor_send_request(pin);
}

/**
 * @brief Map a decoded remote command to its name.
 *
 * @param command Decoded NEC command byte.
 * @return const char* Command name string.
 */
static const char *monitor_ir_name(uint8_t command) {
    if (command == MONITOR_IR_ENTER_COMMAND) return "ENTER";
    if (command == MONITOR_IR_CLEAR_COMMAND) return "CLEAR";
    return "DIGIT";
}

/**
 * @brief Apply one decoded infrared command to the keypad.
 *
 * @param cmd Pointer to the decoded infrared command.
 * @return void
 */
static void monitor_apply_ir(const ir_command_t *cmd) {
    printf("IR %s (0x%02X)\n", monitor_ir_name(cmd->command),
           (unsigned)cmd->command);
    if (cmd->command == MONITOR_IR_ENTER_COMMAND) {
        monitor_handle_enter();
    } else if (cmd->command == MONITOR_IR_CLEAR_COMMAND) {
        keypad_clear();
    } else {
        monitor_apply_digit(monitor_digit_command(cmd->command));
    }
}

/**
 * @brief Poll the infrared eye for a keypad command.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_handle_ir(void) {
    ir_command_t cmd;
    if (!ir_remote_poll(&cmd)) {
        return;
    }
    monitor_apply_ir(&cmd);
}

/**
 * @brief Apply the configured fail mode to an expired authorization request.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_fail_mode(void) {
    if (g_fail_secure) {
        monitor_lock(STATUS_LED_DENIED);
    } else {
        monitor_release();
    }
}

/**
 * @brief Expire the pending wait and the bounded release hold.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_expire(uint64_t now_us) {
    if (g_state == STATUS_LED_PENDING && now_us >= g_pending_until_us) {
        monitor_fail_mode();
    }
    if (g_state == STATUS_LED_GRANTED && now_us >= g_hold_until_us) {
        monitor_lock(STATUS_LED_OFF);
    }
}

/**
 * @brief Service the radio, request-to-exit, infrared, and timers.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_inputs(uint64_t now_us) {
    monitor_heartbeat();
    monitor_rx_tick();
    monitor_handle_rex();
    monitor_handle_ir();
    monitor_expire(now_us);
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_service_inputs(now_us);
    monitor_render();
    return true;
}
