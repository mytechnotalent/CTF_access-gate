/**
 * FILE: stdlib.h
 *
 * DESCRIPTION:
 * Host mock header for Pico SDK stdlib and base abstractions.
 *
 * BRIEF:
 * Pico SDK stdlib mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_PICO_STDLIB_H
#define MOCK_PICO_STDLIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Unsigned integer shorthand matching Pico SDK convention.
 */
typedef unsigned int uint;

/**
 * @brief Direction constant for GPIO output mode.
 */
#define GPIO_OUT true

/**
 * @brief Direction constant for GPIO input mode.
 */
#define GPIO_IN false

/**
 * @brief Return code from getchar_timeout_us when no input is ready.
 */
#define PICO_ERROR_TIMEOUT (-1)

/**
 * @brief Generic negative return code for failed peripheral operations.
 */
#define PICO_ERROR_GENERIC (-1)

/**
 * @brief Mock implementation of tight_loop_contents.
 *
 * @param void No parameters.
 * @return void
 */
static inline void tight_loop_contents(void) {
}

/**
 * @brief Mock implementation of stdio_init_all.
 *
 * @param void No parameters.
 * @return void
 */
static inline void stdio_init_all(void) {
}

#endif // MOCK_PICO_STDLIB_H