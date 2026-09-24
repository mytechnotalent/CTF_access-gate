/**
 * FILE: pwm.h
 *
 * DESCRIPTION:
 * Host mock header for Pico SDK PWM with per-pin level capture.
 *
 * BRIEF:
 * Pico SDK hardware PWM mock for native unit testing.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#ifndef MOCK_HARDWARE_PWM_H
#define MOCK_HARDWARE_PWM_H

#include "pico/stdlib.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Maximum GPIO pin count tracked by the PWM mock.
 */
#define MOCK_PWM_MAX_GPIOS 32u

/**
 * @brief Number of PWM slices tracked by the mock.
 */
#define MOCK_PWM_MAX_SLICES 16u

/**
 * @brief Mutable PWM slice configuration block.
 */
typedef struct pwm_config {
    /**
     * @brief Clock divider applied to the PWM slice.
     */
    float clkdiv;
    /**
     * @brief Wrap value that sets the PWM period.
     */
    uint16_t wrap;
} pwm_config;

/**
 * @brief Recorded last output level per GPIO pin.
 */
uint16_t s_mock_pwm_levels[MOCK_PWM_MAX_GPIOS];

/**
 * @brief Recorded clock divider per PWM slice.
 */
float s_mock_pwm_clkdiv[MOCK_PWM_MAX_SLICES];

/**
 * @brief Recorded wrap value per PWM slice.
 */
uint16_t s_mock_pwm_wrap[MOCK_PWM_MAX_SLICES];

/**
 * @brief Recorded running flag per PWM slice.
 */
bool s_mock_pwm_running[MOCK_PWM_MAX_SLICES];

/**
 * @brief Reset all mock PWM state.
 *
 * @param void No parameters.
 * @return void
 */
static inline void mock_pwm_reset(void) {
    uint i;
    for (i = 0u; i < MOCK_PWM_MAX_GPIOS; ++i) {
        s_mock_pwm_levels[i] = 0u;
    }
    for (i = 0u; i < MOCK_PWM_MAX_SLICES; ++i) {
        s_mock_pwm_clkdiv[i] = 0.0f;
        s_mock_pwm_wrap[i] = 0u;
        s_mock_pwm_running[i] = false;
    }
}

/**
 * @brief Return the recorded PWM level for a GPIO pin.
 *
 * @param gpio Pin number to inspect.
 * @return uint16_t Last level written to the pin, or zero when invalid.
 */
static inline uint16_t mock_pwm_get_level(uint gpio) {
    if (gpio >= MOCK_PWM_MAX_GPIOS) {
        return 0u;
    }
    return s_mock_pwm_levels[gpio];
}

/**
 * @brief Return the recorded clock divider for a PWM slice.
 *
 * @param slice Slice number to inspect.
 * @return float Recorded clock divider, or zero when invalid.
 */
static inline float mock_pwm_get_clkdiv(uint slice) {
    if (slice >= MOCK_PWM_MAX_SLICES) {
        return 0.0f;
    }
    return s_mock_pwm_clkdiv[slice];
}

/**
 * @brief Return the recorded wrap value for a PWM slice.
 *
 * @param slice Slice number to inspect.
 * @return uint16_t Recorded wrap value, or zero when invalid.
 */
static inline uint16_t mock_pwm_get_wrap(uint slice) {
    if (slice >= MOCK_PWM_MAX_SLICES) {
        return 0u;
    }
    return s_mock_pwm_wrap[slice];
}

/**
 * @brief Report whether a PWM slice was started.
 *
 * @param slice Slice number to inspect.
 * @return bool true when the slice was initialized in the running state.
 */
static inline bool mock_pwm_is_running(uint slice) {
    if (slice >= MOCK_PWM_MAX_SLICES) {
        return false;
    }
    return s_mock_pwm_running[slice];
}

/**
 * @brief Mock implementation of pwm_get_default_config.
 *
 * @param void No parameters.
 * @return pwm_config Default configuration block.
 */
static inline pwm_config pwm_get_default_config(void) {
    pwm_config cfg;
    cfg.clkdiv = 1.0f;
    cfg.wrap = 0xFFFFu;
    return cfg;
}

/**
 * @brief Mock implementation of pwm_config_set_clkdiv.
 *
 * @param c Pointer to a mutable PWM configuration block.
 * @param div Clock divider to store.
 * @return void
 */
static inline void pwm_config_set_clkdiv(pwm_config *c, float div) {
    if (c != NULL) {
        c->clkdiv = div;
    }
}

/**
 * @brief Mock implementation of pwm_config_set_wrap.
 *
 * @param c Pointer to a mutable PWM configuration block.
 * @param wrap Wrap value to store.
 * @return void
 */
static inline void pwm_config_set_wrap(pwm_config *c, uint16_t wrap) {
    if (c != NULL) {
        c->wrap = wrap;
    }
}

/**
 * @brief Mock implementation of pwm_init.
 *
 * @param slice PWM slice number being initialized.
 * @param c Pointer to the configuration block to apply.
 * @param start True to start the slice immediately.
 * @return void
 */
static inline void pwm_init(uint slice, const pwm_config *c, bool start) {
    if (slice >= MOCK_PWM_MAX_SLICES || c == NULL) {
        return;
    }
    s_mock_pwm_clkdiv[slice] = c->clkdiv;
    s_mock_pwm_wrap[slice] = c->wrap;
    s_mock_pwm_running[slice] = start;
}

/**
 * @brief Mock implementation of pwm_set_gpio_level.
 *
 * @param gpio Pin number whose level is set.
 * @param level Output level to record.
 * @return void
 */
static inline void pwm_set_gpio_level(uint gpio, uint16_t level) {
    if (gpio < MOCK_PWM_MAX_GPIOS) {
        s_mock_pwm_levels[gpio] = level;
    }
}

/**
 * @brief Mock implementation of pwm_gpio_to_slice_num.
 *
 * @param gpio Pin number to translate.
 * @return uint PWM slice number owning the pin.
 */
static inline uint pwm_gpio_to_slice_num(uint gpio) {
    return (gpio >> 1u) % MOCK_PWM_MAX_SLICES;
}

/**
 * @brief Mock implementation of pwm_gpio_to_channel.
 *
 * @param gpio Pin number to translate.
 * @return uint PWM channel number owning the pin.
 */
static inline uint pwm_gpio_to_channel(uint gpio) {
    return gpio & 1u;
}

#endif // MOCK_HARDWARE_PWM_H
