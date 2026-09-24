/**
 * FILE: time.h
 *
 * DESCRIPTION:
 * Host mock header for the Pico SDK timer with an explicit fake clock.
 *
 * BRIEF:
 * Pico SDK time mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_PICO_TIME_H
#define MOCK_PICO_TIME_H

#include <stdint.h>

/**
 * @brief One absolute tick counter in microseconds.
 */
uint64_t s_mock_time_us;

/**
 * @brief Mock implementation of time_us_64 with a one-microsecond advance.
 *
 * Each read advances the fake clock by one microsecond so busy-wait
 * loops that poll the clock make deterministic progress in host tests.
 *
 * @param void No parameters.
 * @return uint64_t Current fake clock value before the advance.
 */
static inline uint64_t time_us_64(void) {
    return s_mock_time_us++;
}

/**
 * @brief Mock implementation of sleep_us.
 *
 * @param us Number of microseconds to elapse.
 * @return void
 */
static inline void sleep_us(uint64_t us) {
    s_mock_time_us += us;
}

/**
 * @brief Mock implementation of sleep_ms.
 *
 * @param ms Number of milliseconds to elapse.
 * @return void
 */
static inline void sleep_ms(uint32_t ms) {
    s_mock_time_us += (uint64_t)ms * 1000u;
}

/**
 * @brief Reset the fake clock to zero.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_timer_reset(void) {
    s_mock_time_us = 0u;
}

/**
 * @brief Set the fake clock to an explicit value.
 *
 * @param value Absolute fake clock value in microseconds.
 * @return void
 */
static inline void mock_timer_set_us(uint64_t value) {
    s_mock_time_us = value;
}

/**
 * @brief Read the current fake clock without advancing it.
 *
 * @param void No parameters.
 * @return uint64_t Current fake clock value in microseconds.
 */
static inline uint64_t mock_timer_now_us(void) {
    return s_mock_time_us;
}

#endif // MOCK_PICO_TIME_H