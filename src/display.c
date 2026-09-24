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
// File:    display.c
// Desc:    Implements the HD44780 1602 LCD driver over the PCF8574 I2C
//          backpack and the two-line monitor renderer.
// Created: 2026

#include "access_gate.h"
#include "display.h"
#include "hardware/i2c.h"
#include "pico/time.h"
#include <stdio.h>

/**
 * @brief I2C control bit for the register-select line.
 */
#define LCD_CTRL_RS 0x01u

/**
 * @brief I2C control bit for the enable strobe line.
 */
#define LCD_CTRL_EN 0x04u

/**
 * @brief I2C control bit for the backpack backlight LED.
 */
#define LCD_CTRL_BL 0x08u

/**
 * @brief HD44780 clear-display command value.
 */
#define LCD_CMD_CLEAR 0x01u

/**
 * @brief Write one byte with a full enable pulse on the I2C line.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @param byte Bits to place on the PCF8574 port after the pulse.
 * @return void
 */
static void lcd_pulse_en(i2c_inst_t *i2c, uint8_t addr, uint8_t byte) {
    uint8_t high = (uint8_t)(byte | LCD_CTRL_EN);
    uint8_t low = (uint8_t)(byte & ~LCD_CTRL_EN);
    high = (uint8_t)(high | LCD_CTRL_BL);
    low = (uint8_t)(low | LCD_CTRL_BL);
    i2c_write_blocking(i2c, addr, &high, 1u, false);
    sleep_us(1u);
    i2c_write_blocking(i2c, addr, &low, 1u, false);
    sleep_us(50u);
}

/**
 * @brief Transmit one 4-bit nibble with control flags.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @param nibble Low nibble to place on the display data lines.
 * @param ctrl Register-select and other control bits.
 * @return void
 */
static void lcd_nibble(i2c_inst_t *i2c, uint8_t addr, uint8_t nibble,
                       uint8_t ctrl) {
    uint8_t byte;
    byte = (uint8_t)(((nibble << 4u) & 0xF0u) | ctrl);
    lcd_pulse_en(i2c, addr, byte);
}

/**
 * @brief Write one HD44780 command byte.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @param cmd Value to write to the command register.
 * @return void
 */
static void lcd_cmd(i2c_inst_t *i2c, uint8_t addr, uint8_t cmd) {
    lcd_nibble(i2c, addr, (uint8_t)(cmd >> 4u), 0u);
    lcd_nibble(i2c, addr, (uint8_t)(cmd & 0x0Fu), 0u);
    if (cmd == LCD_CMD_CLEAR) {
        sleep_ms(2u);
    }
}

/**
 * @brief Write one HD44780 data byte to the character RAM.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @param byte Value to write to the data register.
 * @return void
 */
static void lcd_data(i2c_inst_t *i2c, uint8_t addr, uint8_t byte) {
    lcd_nibble(i2c, addr, (uint8_t)(byte >> 4u), LCD_CTRL_RS);
    lcd_nibble(i2c, addr, (uint8_t)(byte & 0x0Fu), LCD_CTRL_RS);
}

/**
 * @brief Drive the HD44780 8-bit-to-4-bit wake-up nibble sequence.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @return void
 */
static void lcd_wake(i2c_inst_t *i2c, uint8_t addr) {
    lcd_nibble(i2c, addr, 0x03u, 0u);
    sleep_ms(5u);
    lcd_nibble(i2c, addr, 0x03u, 0u);
    sleep_us(150u);
    lcd_nibble(i2c, addr, 0x03u, 0u);
    lcd_nibble(i2c, addr, 0x02u, 0u);
}

/**
 * @brief Program the HD44780 function, display, clear, and entry commands.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @return void
 */
static void lcd_setup(i2c_inst_t *i2c, uint8_t addr) {
    lcd_cmd(i2c, addr, 0x28u);
    lcd_cmd(i2c, addr, 0x0Cu);
    lcd_cmd(i2c, addr, LCD_CMD_CLEAR);
    lcd_cmd(i2c, addr, 0x06u);
}

bool display_init(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t probe = (uint8_t)(0x03u | LCD_CTRL_BL);
    sleep_ms(50u);
    if (i2c_write_blocking(i2c, addr, &probe, 1u, false) < 0) {
        return false;
    }
    lcd_wake(i2c, addr);
    lcd_setup(i2c, addr);
    return true;
}

/**
 * @brief Render the temperature and humidity line.
 *
 * @param reading Pointer to the decoded DHT11 reading.
 * @param line1 Pointer to mutable first-line buffer.
 * @return void
 */
static void format_temp_line(const dht_reading_t *reading, char *line1) {
    int t_tenths = (int)reading->temperature_tenths;
    int t_dec = t_tenths % 10;
    if (t_dec < 0) {
        t_dec = -t_dec;
    }
    snprintf(line1, DISPLAY_LINE_LEN, "T:%d.%dC H:%u.%u%%", t_tenths / 10,
             t_dec, (unsigned)reading->humidity_tenths / 10u,
             (unsigned)reading->humidity_tenths % 10u);
}

void display_format_lines(const dht_reading_t *reading, uint16_t seq, bool tx_ok,
                          char *line1, char *line2) {
    format_temp_line(reading, line1);
    snprintf(line2, DISPLAY_LINE_LEN, "N:%02u S:%04u %s",
             (unsigned)PACKET_NODE_ID, (unsigned)seq, tx_ok ? "OK" : "!!");
}

/**
 * @brief Write one padded LCD row at a DDRAM address command.
 *
 * @param i2c Pointer to the I2C peripheral the backpack is wired to.
 * @param addr The 7-bit I2C address of the backpack.
 * @param cmd DDRAM address command byte.
 * @param text Pointer to the text to render.
 * @return void
 */
static void lcd_write_row(i2c_inst_t *i2c, uint8_t addr, uint8_t cmd,
                          const char *text) {
    uint8_t i;
    lcd_cmd(i2c, addr, cmd);
    for (i = 0u; i < DISPLAY_COLS; ++i) {
        char ch = text[i] ? text[i] : ' ';
        lcd_data(i2c, addr, (uint8_t)ch);
    }
}

void display_render_lines(i2c_inst_t *i2c, uint8_t addr, const char *line1,
                          const char *line2) {
    lcd_write_row(i2c, addr, 0x80u, line1);
    lcd_write_row(i2c, addr, (uint8_t)(0x80u | DISPLAY_LINE2_ADDR), line2);
}