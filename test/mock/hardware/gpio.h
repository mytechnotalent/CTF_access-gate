/**
 * FILE: gpio.h
 *
 * DESCRIPTION:
 * Host mock header for Pico SDK GPIO with a DHT11 waveform timeline.
 *
 * BRIEF:
 * Pico SDK hardware GPIO mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_HARDWARE_GPIO_H
#define MOCK_HARDWARE_GPIO_H

#include "pico/stdlib.h"
#include "pico/time.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Maximum GPIO pin count tracked by mock.
 */
#define MOCK_MAX_GPIOS 32u

/**
 * @brief GPIO function constant for UART signals.
 */
#define GPIO_FUNC_UART 1u

/**
 * @brief GPIO function constant for I2C signals.
 */
#define GPIO_FUNC_I2C 2u

/**
 * @brief Recorded GPIO output levels.
 */
int s_mock_gpio_levels[MOCK_MAX_GPIOS];

/**
 * @brief Recorded GPIO directions.
 */
bool s_mock_gpio_dirs[MOCK_MAX_GPIOS];

/**
 * @brief Recorded GPIO output toggles.
 */
uint32_t s_mock_gpio_toggles[MOCK_MAX_GPIOS];

/**
 * @brief Pin index driving the DHT waveform timeline.
 */
uint s_mock_timeline_pin;

/**
 * @brief True when the DHT waveform timeline is active.
 */
bool s_mock_timeline_active;

/**
 * @brief Absolute time base of the current timeline.
 */
uint64_t s_mock_timeline_base;

/**
 * @brief Current index in the timeline arrays.
 */
size_t s_mock_timeline_index;

/**
 * @brief Offset entries of the waveform timeline.
 */
const uint32_t *s_mock_timeline_offsets;

/**
 * @brief Level entries of the waveform timeline.
 */
const int *s_mock_timeline_levels;

/**
 * @brief Number of entries in the waveform timeline.
 */
size_t s_mock_timeline_count;

/**
 * @brief Reset mock GPIO pin states.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_gpio_reset(void) {
    size_t i;
    for (i = 0u; i < MOCK_MAX_GPIOS; ++i) {
        s_mock_gpio_levels[i] = 0;
        s_mock_gpio_dirs[i] = false;
        s_mock_gpio_toggles[i] = 0u;
    }
    s_mock_timeline_active = false;
    s_mock_timeline_index = 0u;
    s_mock_timeline_count = 0u;
}

/**
 * @brief Arm the DHT waveform timeline at an explicit time base.
 *
 * @param base Absolute fake-clock time in microseconds.
 * @param offsets Pointer to ascending relative-edge offsets.
 * @param levels Pointer to matching edge levels.
 * @param count Number of timeline entries.
 * @param pin GPIO pin driven by the timeline.
 * @return void
 */
static inline void mock_gpio_timeline_begin_at(
    uint64_t base, const uint32_t *offsets, const int *levels, size_t count,
    uint pin) {
    s_mock_timeline_base = base;
    s_mock_timeline_offsets = offsets;
    s_mock_timeline_levels = levels;
    s_mock_timeline_index = 0u;
    s_mock_timeline_count = count;
    s_mock_timeline_pin = pin;
    s_mock_timeline_active = true;
}

/**
 * @brief Disarm the DHT waveform timeline.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_gpio_timeline_end(void) {
    s_mock_timeline_active = false;
    s_mock_timeline_count = 0u;
    s_mock_timeline_index = 0u;
}

/**
 * @brief Query the number of recorded output toggles on a pin.
 *
 * @param gpio Pin number to inspect.
 * @return uint32_t Number of output level changes recorded.
 */
static inline uint32_t mock_gpio_toggles(uint gpio) {
    if (gpio >= MOCK_MAX_GPIOS) {
        return 0u;
    }
    return s_mock_gpio_toggles[gpio];
}

/**
 * @brief Query current mock GPIO output state.
 *
 * @param gpio Pin number to inspect.
 * @return int Recorded pin level (0 or 1), or -1 if invalid pin.
 */
static inline int mock_gpio_get(uint gpio) {
    if (gpio >= MOCK_MAX_GPIOS) {
        return -1;
    }
    return s_mock_gpio_levels[gpio];
}

/**
 * @brief Mock implementation of gpio_init.
 *
 * @param gpio Pin number being initialized.
 * @return void
 */
static inline void gpio_init(uint gpio) {
    if (gpio < MOCK_MAX_GPIOS) {
        s_mock_gpio_levels[gpio] = 0;
        s_mock_gpio_dirs[gpio] = false;
    }
}

/**
 * @brief Mock implementation of gpio_set_dir.
 *
 * @param gpio Pin number.
 * @param out True for output, false for input.
 * @return void
 */
static inline void gpio_set_dir(uint gpio, bool out) {
    if (gpio < MOCK_MAX_GPIOS) {
        s_mock_gpio_dirs[gpio] = out;
    }
}

/**
 * @brief Mock implementation of gpio_put.
 *
 * @param gpio Pin number.
 * @param value Output level (0 or 1).
 * @return void
 */
static inline void gpio_put(uint gpio, bool value) {
    if (gpio < MOCK_MAX_GPIOS) {
        int level = value ? 1 : 0;
        if (level != s_mock_gpio_levels[gpio]) {
            s_mock_gpio_toggles[gpio] += 1u;
        }
        s_mock_gpio_levels[gpio] = level;
    }
}

/**
 * @brief Advance the armed waveform timeline up to the current mock time.
 *
 * @param gpio Pin number whose level tracks the timeline.
 * @return void
 */
static inline void mock_gpio_advance(uint gpio) {
    while (s_mock_timeline_index < s_mock_timeline_count &&
           (s_mock_timeline_base +
            s_mock_timeline_offsets[s_mock_timeline_index]) <= s_mock_time_us) {
        s_mock_gpio_levels[gpio] = s_mock_timeline_levels[s_mock_timeline_index];
        s_mock_timeline_index += 1u;
    }
}

/**
 * @brief Mock implementation of gpio_get.
 *
 * The timeline pin reads its level from the armed waveform timeline.
 *
 * @param gpio Pin number.
 * @return int Current pin level (0 or 1), or -1 if invalid pin.
 */
static inline int gpio_get(uint gpio) {
    if (gpio >= MOCK_MAX_GPIOS) {
        return -1;
    }
    if (s_mock_timeline_active && gpio == s_mock_timeline_pin) {
        mock_gpio_advance(gpio);
    }
    return s_mock_gpio_levels[gpio];
}

/**
 * @brief Mock implementation of gpio_pull_up.
 *
 * @param gpio Pin number.
 * @return void
 */
static inline void gpio_pull_up(uint gpio) {
    (void)gpio;
}

/**
 * @brief Mock implementation of gpio_set_function.
 *
 * @param gpio Pin number.
 * @param fn_dummy Function selector constant.
 * @return void
 */
static inline void gpio_set_function(uint gpio, uint fn_dummy) {
    (void)gpio;
    (void)fn_dummy;
}

#endif // MOCK_HARDWARE_GPIO_H