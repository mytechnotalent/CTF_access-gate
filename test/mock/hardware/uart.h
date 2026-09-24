/**
 * FILE: uart.h
 *
 * DESCRIPTION:
 * Host mock header for Pico SDK UART with transmit and receive rings.
 *
 * BRIEF:
 * Pico SDK hardware UART mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_HARDWARE_UART_H
#define MOCK_HARDWARE_UART_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Capacity of mock UART transmit and receive buffers.
 */
#define MOCK_UART_BUF_SIZE 2048u

/**
 * @brief Recorded UART baud rate from the most recent uart_init call.
 */
uint32_t s_mock_uart_baud;

/**
 * @brief Opaque UART peripheral handle type.
 */
typedef struct mock_uart_t {
    int unused;
} uart_inst_t;

/**
 * @brief Backing instance for the uart0 peripheral alias.
 */
uart_inst_t s_mock_uart0_instance;

/**
 * @brief Alias matching the RP2350 uart0 peripheral symbol.
 */
#define uart0 (&s_mock_uart0_instance)

/**
 * @brief Backing instance for the uart1 peripheral alias.
 */
uart_inst_t s_mock_uart1_instance;

/**
 * @brief Alias matching the RP2350 uart1 peripheral symbol.
 */
#define uart1 (&s_mock_uart1_instance)

/**
 * @brief Mock UART transmitted bytes.
 */
char s_mock_tx_buf[MOCK_UART_BUF_SIZE];

/**
 * @brief Number of bytes currently in mock UART transmit buffer.
 */
size_t s_mock_tx_len;

/**
 * @brief Mock UART incoming bytes buffer for uart_getc.
 */
char s_mock_rx_buf[MOCK_UART_BUF_SIZE];

/**
 * @brief Total length of incoming bytes in mock UART receive buffer.
 */
size_t s_mock_rx_len;

/**
 * @brief Current read index in mock UART receive buffer.
 */
size_t s_mock_rx_pos;

/**
 * @brief Reset mock UART transmit and receive buffers.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_uart_reset(void) {
    s_mock_uart_baud = 0u;
    s_mock_tx_len = 0u;
    s_mock_rx_len = 0u;
    s_mock_rx_pos = 0u;
    memset(s_mock_tx_buf, 0, sizeof(s_mock_tx_buf));
    memset(s_mock_rx_buf, 0, sizeof(s_mock_rx_buf));
}

/**
 * @brief Copy transmitted UART bytes into a caller buffer.
 *
 * @param buf Destination buffer.
 * @param max_len Maximum bytes to copy.
 * @return size_t Number of bytes copied.
 */
static inline size_t mock_uart_get_tx(char *buf, size_t max_len) {
    size_t copy_len;
    if (buf == NULL || max_len == 0u) {
        return 0u;
    }
    copy_len = (s_mock_tx_len < max_len) ? s_mock_tx_len : max_len;
    memcpy(buf, s_mock_tx_buf, copy_len);
    return copy_len;
}

/**
 * @brief Prime the mock UART receive buffer with test characters.
 *
 * @param input Input string of characters to supply to uart_getc.
 * @param len Number of characters in input.
 * @return void
 */
static inline void mock_uart_set_rx(const char *input, size_t len) {
    size_t copy_len;
    s_mock_rx_pos = 0u;
    if (input == NULL || len == 0u) {
        s_mock_rx_len = 0u;
        return;
    }
    copy_len = (len < MOCK_UART_BUF_SIZE) ? len : MOCK_UART_BUF_SIZE;
    memcpy(s_mock_rx_buf, input, copy_len);
    s_mock_rx_len = copy_len;
}

/**
 * @brief Mock implementation of uart_init.
 *
 * @param uart Pointer to a UART peripheral.
 * @param baud Baud rate to configure.
 * @return void
 */
static inline void uart_init(uart_inst_t *uart, uint32_t baud) {
    (void)uart;
    s_mock_uart_baud = baud;
}

/**
 * @brief Mock implementation of uart_set_fifo_enabled.
 *
 * @param uart Pointer to a UART peripheral.
 * @param enabled True to enable the hardware FIFO.
 * @return void
 */
static inline void uart_set_fifo_enabled(uart_inst_t *uart, bool enabled) {
    (void)uart;
    (void)enabled;
}

/**
 * @brief Mock implementation of uart_is_readable.
 *
 * @param uart Pointer to a UART peripheral.
 * @return bool true when receive bytes remain buffered.
 */
static inline bool uart_is_readable(uart_inst_t *uart) {
    (void)uart;
    return s_mock_rx_pos < s_mock_rx_len;
}

/**
 * @brief Mock implementation of uart_getc.
 *
 * @param uart Pointer to a UART peripheral.
 * @return int Next buffered character or -1 when empty.
 */
static inline int uart_getc(uart_inst_t *uart) {
    (void)uart;
    if (s_mock_rx_pos < s_mock_rx_len) {
        return (unsigned char)s_mock_rx_buf[s_mock_rx_pos++];
    }
    return -1;
}

/**
 * @brief Mock implementation of uart_write_blocking.
 *
 * @param uart Pointer to a UART peripheral.
 * @param src Pointer to bytes to transmit.
 * @param len Number of bytes to transmit.
 * @return void
 */
static inline void uart_write_blocking(uart_inst_t *uart, const uint8_t *src,
                                       size_t len) {
    size_t i;
    (void)uart;
    for (i = 0u; i < len && s_mock_tx_len < MOCK_UART_BUF_SIZE; ++i) {
        s_mock_tx_buf[s_mock_tx_len] = (char)src[i];
        s_mock_tx_len += 1u;
    }
}

#endif // MOCK_HARDWARE_UART_H