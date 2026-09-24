/**
 * FILE: i2c.h
 *
 * DESCRIPTION:
 * Host mock header for Pico SDK I2C with a write byte log.
 *
 * BRIEF:
 * Pico SDK hardware I2C mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_HARDWARE_I2C_H
#define MOCK_HARDWARE_I2C_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Capacity of the mock I2C write log.
 */
#define MOCK_I2C_LOG_SIZE 4096u

/**
 * @brief Opaque I2C peripheral handle type.
 */
typedef struct mock_i2c_t {
    int unused;
} i2c_inst_t;

/**
 * @brief Backing instance for the i2c1 peripheral alias.
 */
i2c_inst_t s_mock_i2c1_instance;

/**
 * @brief Alias matching the RP2350 i2c1 peripheral symbol.
 */
#define i2c1 (&s_mock_i2c1_instance)

/**
 * @brief Mock I2C write log bytes.
 */
uint8_t s_mock_i2c_log[MOCK_I2C_LOG_SIZE];

/**
 * @brief Number of bytes currently in the mock I2C write log.
 */
size_t s_mock_i2c_log_len;

/**
 * @brief Force all mock I2C writes to fail.
 */
bool s_mock_i2c_write_fail;

/**
 * @brief Reset the mock I2C write log.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_i2c_reset(void) {
    s_mock_i2c_log_len = 0u;
    s_mock_i2c_write_fail = false;
}

/**
 * @brief Set whether subsequent mock I2C writes report failure.
 *
 * @param fail True to force every write to return an error.
 * @return void
 */
static inline void mock_i2c_set_write_fail(bool fail) {
    s_mock_i2c_write_fail = fail;
}

/**
 * @brief Copy the mock I2C write log into a caller buffer.
 *
 * @param buf Destination buffer.
 * @param max_len Maximum bytes to copy.
 * @return size_t Number of bytes copied.
 */
static inline size_t mock_i2c_get_log(uint8_t *buf, size_t max_len) {
    size_t copy_len = (s_mock_i2c_log_len < max_len) ? s_mock_i2c_log_len
                                                     : max_len;
    size_t i;
    for (i = 0u; i < copy_len; ++i) {
        buf[i] = s_mock_i2c_log[i];
    }
    return copy_len;
}

/**
 * @brief Return the current mock I2C write log length.
 *
 * @param void No parameters.
 * @return size_t Number of recorded write bytes.
 */
static inline size_t mock_i2c_log_count(void) {
    return s_mock_i2c_log_len;
}

/**
 * @brief Mock implementation of i2c_init.
 *
 * @param i2c Pointer to an I2C peripheral.
 * @param baud Baud rate in Hz.
 * @return i2c_inst_t* Peripheral handle for chaining.
 */
static inline i2c_inst_t *i2c_init(i2c_inst_t *i2c, uint baud) {
    (void)i2c;
    (void)baud;
    return i2c;
}

/**
 * @brief Append bytes to the mock I2C log up to its capacity.
 *
 * @param src Pointer to bytes to store.
 * @param len Number of bytes offered.
 * @return size_t Number of bytes stored.
 */
static inline size_t mock_i2c_store(const uint8_t *src, size_t len) {
    size_t i;
    for (i = 0u; i < len && s_mock_i2c_log_len < MOCK_I2C_LOG_SIZE; ++i) {
        s_mock_i2c_log[s_mock_i2c_log_len] = src[i];
        s_mock_i2c_log_len += 1u;
    }
    return i;
}

/**
 * @brief Mock implementation of i2c_write_blocking.
 *
 * @param i2c Pointer to an I2C peripheral.
 * @param addr 7-bit slave address.
 * @param src Pointer to bytes to write.
 * @param len Number of bytes to write.
 * @param nostop True to hold the bus between transactions.
 * @return int Number of bytes written.
 */
static inline int i2c_write_blocking(i2c_inst_t *i2c, uint8_t addr,
                                     const uint8_t *src, size_t len,
                                     bool nostop) {
    (void)i2c;
    (void)addr;
    (void)nostop;
    if (s_mock_i2c_write_fail) {
        return PICO_ERROR_GENERIC;
    }
    return (int)mock_i2c_store(src, len);
}

#endif // MOCK_HARDWARE_I2C_H