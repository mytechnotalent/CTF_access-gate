/**
 * FILE: rand.h
 *
 * DESCRIPTION:
 * Host mock header for the Pico SDK random source with a deterministic
 * counter-valued word sequence.
 *
 * BRIEF:
 * Pico SDK random mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_PICO_RAND_H
#define MOCK_PICO_RAND_H

#include <stdint.h>

/**
 * @brief Counter driving the deterministic mock random words.
 */
uint32_t s_mock_rand_counter;

/**
 * @brief Reset the deterministic mock random counter to zero.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_rand_reset(void) {
    s_mock_rand_counter = 0u;
}

/**
 * @brief Mock implementation of get_rand_32 with a counter sequence.
 *
 * Returns the current counter value and then increments it so successive
 * calls produce the deterministic words zero, one, two, and so on.
 *
 * @param void No parameters.
 * @return uint32_t Next deterministic pseudo-random word.
 */
static inline uint32_t get_rand_32(void) {
    return s_mock_rand_counter++;
}

#endif // MOCK_PICO_RAND_H
