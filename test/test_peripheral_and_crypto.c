/**
 * FILE: test_peripheral_and_crypto.c
 *
 * DESCRIPTION:
 * Native unit tests for the RP2350 Cold Chain Agricultural Environmental
 * Monitor status LED, button, servo, infrared decoder, the ChaCha20,
 * Poly1305, XChaCha20-Poly1305, BLAKE2b, and Argon2id security modules,
 * and the monitor input handlers that consume those peripherals.
 *
 * BRIEF:
 * Peripheral and security module native test translation unit.
 *
 * AUTHOR: Kevin Thomas
 * DATE: September 2026
 */

#include "mock/pico/stdlib.h"
#include "harness.h"
#include "mock/pico/time.h"
#include "mock/hardware/gpio.h"
#include "mock/hardware/pwm.h"
#include "access_gate.h"
#include "status_led.h"
#include "button.h"
#include "servo.h"
#include "ir_remote.h"
#include "monitor.h"
#include "chacha20.h"
#include "poly1305.h"
#include "crypto_aead.h"
#include "blake2b.h"
#include "argon2.h"
#include "crypto_kdf.h"
#include "envelope.h"
#include <string.h>

#include "../src/status_led.c"
#include "../src/button.c"
#include "../src/servo.c"
#include "../src/ir_remote.c"
#include "../src/chacha20.c"
#include "../src/poly1305.c"
#include "../src/crypto_aead.c"
#include "../src/blake2b.c"
#include "../src/argon2.c"
#include "../src/crypto_kdf.c"
#include "../src/envelope.c"

/**
 * @brief RFC 8439 ChaCha20 key bytes zero through thirty-one.
 */
static const uint8_t s_rfc_key[32] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
};

/**
 * @brief RFC 8439 block-function nonce.
 */
static const uint8_t s_rfc_nonce[12] = {
    0x00u, 0x00u, 0x00u, 0x09u, 0x00u, 0x00u, 0x00u, 0x4Au,
    0x00u, 0x00u, 0x00u, 0x00u,
};

/**
 * @brief RFC 8439 block-function keystream vector.
 */
static const uint8_t s_rfc_block[64] = {
    0x10u, 0xF1u, 0xE7u, 0xE4u, 0xD1u, 0x3Bu, 0x59u, 0x15u,
    0x50u, 0x0Fu, 0xDDu, 0x1Fu, 0xA3u, 0x20u, 0x71u, 0xC4u,
    0xC7u, 0xD1u, 0xF4u, 0xC7u, 0x33u, 0xC0u, 0x68u, 0x03u,
    0x04u, 0x22u, 0xAAu, 0x9Au, 0xC3u, 0xD4u, 0x6Cu, 0x4Eu,
    0xD2u, 0x82u, 0x64u, 0x46u, 0x07u, 0x9Fu, 0xAAu, 0x09u,
    0x14u, 0xC2u, 0xD7u, 0x05u, 0xD9u, 0x8Bu, 0x02u, 0xA2u,
    0xB5u, 0x12u, 0x9Cu, 0xD1u, 0xDEu, 0x16u, 0x4Eu, 0xB9u,
    0xCBu, 0xD0u, 0x83u, 0xE8u, 0xA2u, 0x50u, 0x3Cu, 0x4Eu,
};

/**
 * @brief RFC 8439 stream-cipher nonce.
 */
static const uint8_t s_stream_nonce[12] = {
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x4Au,
    0x00u, 0x00u, 0x00u, 0x00u,
};

/**
 * @brief RFC 8439 stream-cipher plaintext.
 */
static const uint8_t s_stream_pt[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";

/**
 * @brief RFC 8439 stream-cipher ciphertext vector.
 */
static const uint8_t s_stream_ct[114] = {
    0x6Eu, 0x2Eu, 0x35u, 0x9Au, 0x25u, 0x68u, 0xF9u, 0x80u,
    0x41u, 0xBAu, 0x07u, 0x28u, 0xDDu, 0x0Du, 0x69u, 0x81u,
    0xE9u, 0x7Eu, 0x7Au, 0xECu, 0x1Du, 0x43u, 0x60u, 0xC2u,
    0x0Au, 0x27u, 0xAFu, 0xCCu, 0xFDu, 0x9Fu, 0xAEu, 0x0Bu,
    0xF9u, 0x1Bu, 0x65u, 0xC5u, 0x52u, 0x47u, 0x33u, 0xABu,
    0x8Fu, 0x59u, 0x3Du, 0xABu, 0xCDu, 0x62u, 0xB3u, 0x57u,
    0x16u, 0x39u, 0xD6u, 0x24u, 0xE6u, 0x51u, 0x52u, 0xABu,
    0x8Fu, 0x53u, 0x0Cu, 0x35u, 0x9Fu, 0x08u, 0x61u, 0xD8u,
    0x07u, 0xCAu, 0x0Du, 0xBFu, 0x50u, 0x0Du, 0x6Au, 0x61u,
    0x56u, 0xA3u, 0x8Eu, 0x08u, 0x8Au, 0x22u, 0xB6u, 0x5Eu,
    0x52u, 0xBCu, 0x51u, 0x4Du, 0x16u, 0xCCu, 0xF8u, 0x06u,
    0x81u, 0x8Cu, 0xE9u, 0x1Au, 0xB7u, 0x79u, 0x37u, 0x36u,
    0x5Au, 0xF9u, 0x0Bu, 0xBFu, 0x74u, 0xA3u, 0x5Bu, 0xE6u,
    0xB4u, 0x0Bu, 0x8Eu, 0xEDu, 0xF2u, 0x78u, 0x5Eu, 0x42u,
    0x87u, 0x4Du,
};

/**
 * @brief XChaCha20 draft HChaCha20 extended nonce.
 */
static const uint8_t s_hchacha_nonce[16] = {
    0x00u, 0x00u, 0x00u, 0x09u, 0x00u, 0x00u, 0x00u, 0x4Au,
    0x00u, 0x00u, 0x00u, 0x00u, 0x31u, 0x41u, 0x59u, 0x27u,
};

/**
 * @brief XChaCha20 draft HChaCha20 subkey vector.
 */
static const uint8_t s_hchacha_out[32] = {
    0x82u, 0x41u, 0x3Bu, 0x42u, 0x27u, 0xB2u, 0x7Bu, 0xFEu,
    0xD3u, 0x0Eu, 0x42u, 0x50u, 0x8Au, 0x87u, 0x7Du, 0x73u,
    0xA0u, 0xF9u, 0xE4u, 0xD5u, 0x8Au, 0x74u, 0xA8u, 0x53u,
    0xC1u, 0x2Eu, 0xC4u, 0x13u, 0x26u, 0xD3u, 0xECu, 0xDCu,
};

/**
 * @brief RFC 8439 Poly1305 one-time key.
 */
static const uint8_t s_poly_key[32] = {
    0x85u, 0xD6u, 0xBEu, 0x78u, 0x57u, 0x55u, 0x6Du, 0x33u,
    0x7Fu, 0x44u, 0x52u, 0xFEu, 0x42u, 0xD5u, 0x06u, 0xA8u,
    0x01u, 0x03u, 0x80u, 0x8Au, 0xFBu, 0x0Du, 0xB2u, 0xFDu,
    0x4Au, 0xBFu, 0xF6u, 0xAFu, 0x41u, 0x49u, 0xF5u, 0x1Bu,
};

/**
 * @brief RFC 8439 Poly1305 message.
 */
static const uint8_t s_poly_msg[] = "Cryptographic Forum Research Group";

/**
 * @brief RFC 8439 Poly1305 tag vector.
 */
static const uint8_t s_poly_tag[16] = {
    0xA8u, 0x06u, 0x1Du, 0xC1u, 0x30u, 0x51u, 0x36u, 0xC6u,
    0xC2u, 0x2Bu, 0x8Bu, 0xAFu, 0x0Cu, 0x01u, 0x27u, 0xA9u,
};

/**
 * @brief BLAKE2b-512 digest of the ASCII string abc.
 */
static const uint8_t s_blake_abc[64] = {
    0xBAu, 0x80u, 0xA5u, 0x3Fu, 0x98u, 0x1Cu, 0x4Du, 0x0Du,
    0x6Au, 0x27u, 0x97u, 0xB6u, 0x9Fu, 0x12u, 0xF6u, 0xE9u,
    0x4Cu, 0x21u, 0x2Fu, 0x14u, 0x68u, 0x5Au, 0xC4u, 0xB7u,
    0x4Bu, 0x12u, 0xBBu, 0x6Fu, 0xDBu, 0xFFu, 0xA2u, 0xD1u,
    0x7Du, 0x87u, 0xC5u, 0x39u, 0x2Au, 0xABu, 0x79u, 0x2Du,
    0xC2u, 0x52u, 0xD5u, 0xDEu, 0x45u, 0x33u, 0xCCu, 0x95u,
    0x18u, 0xD3u, 0x8Au, 0xA8u, 0xDBu, 0xF1u, 0x92u, 0x5Au,
    0xB9u, 0x23u, 0x86u, 0xEDu, 0xD4u, 0x00u, 0x99u, 0x23u,
};

/**
 * @brief BLAKE2b-512 digest of two hundred 0x5A bytes.
 */
static const uint8_t s_blake_5a[64] = {
    0x33u, 0x52u, 0x2Cu, 0x87u, 0xB5u, 0x93u, 0xDDu, 0x57u,
    0x08u, 0x23u, 0x50u, 0xA3u, 0x4Du, 0xDFu, 0x00u, 0xBAu,
    0x43u, 0xF4u, 0xDCu, 0xADu, 0x36u, 0xD8u, 0xACu, 0xCBu,
    0xB3u, 0x0Au, 0x16u, 0x4Eu, 0xBDu, 0x79u, 0x2Au, 0xC9u,
    0x8Cu, 0x55u, 0xB3u, 0x39u, 0x55u, 0x2Du, 0x6Cu, 0x59u,
    0xBCu, 0x89u, 0xD0u, 0xCAu, 0x84u, 0x59u, 0xAFu, 0x0Eu,
    0x59u, 0xCAu, 0x18u, 0xC4u, 0xADu, 0x2Cu, 0xBDu, 0x91u,
    0x97u, 0xCEu, 0x6Eu, 0x0Cu, 0x0Bu, 0x8Eu, 0x75u, 0x56u,
};

/**
 * @brief Argon2 variable-length hash H' of {1,2,3,4} at thirty-two bytes.
 */
static const uint8_t s_hprime_32[32] = {
    0x9Cu, 0x1Au, 0x99u, 0xE2u, 0xFBu, 0x51u, 0xF9u, 0xC6u,
    0x3Bu, 0xB0u, 0x06u, 0x1Cu, 0x1Au, 0x03u, 0x22u, 0xB3u,
    0x24u, 0x8Cu, 0x98u, 0x7Fu, 0x23u, 0x1Du, 0x59u, 0xEFu,
    0x31u, 0xA1u, 0xE6u, 0x4Au, 0x9Fu, 0x60u, 0x66u, 0x15u,
};

/**
 * @brief Argon2 variable-length hash H' of {1,2,3,4} at two hundred
 * fifty-six bytes.
 */
static const uint8_t s_hprime_256[256] = {
    0x20u, 0xC8u, 0xB1u, 0x54u, 0xD2u, 0xCFu, 0xAAu, 0x48u,
    0x86u, 0x34u, 0x41u, 0xC8u, 0x99u, 0xE8u, 0x53u, 0x84u,
    0x52u, 0x57u, 0xCAu, 0x44u, 0x07u, 0xD6u, 0xF6u, 0xDFu,
    0xFCu, 0x2Bu, 0x66u, 0x9Du, 0xBDu, 0xA1u, 0xB8u, 0x49u,
    0xC5u, 0xE1u, 0x12u, 0x2Fu, 0x9Fu, 0x22u, 0x84u, 0xF1u,
    0xC1u, 0x4Du, 0x56u, 0x9Fu, 0x70u, 0xCFu, 0xB8u, 0xDAu,
    0xE5u, 0xFDu, 0x55u, 0x4Fu, 0x53u, 0xE9u, 0xD7u, 0xB1u,
    0x3Au, 0xCBu, 0x9Bu, 0x71u, 0x04u, 0xACu, 0x02u, 0xD8u,
    0xF3u, 0x16u, 0xA4u, 0xFBu, 0x1Au, 0xBCu, 0xE7u, 0xDCu,
    0x41u, 0x65u, 0xABu, 0xFCu, 0xA8u, 0x52u, 0x32u, 0xD1u,
    0x33u, 0xE9u, 0xEBu, 0xE4u, 0xFDu, 0x85u, 0xDFu, 0xF2u,
    0xBFu, 0x49u, 0xF9u, 0xFEu, 0x29u, 0xB7u, 0xA7u, 0xA3u,
    0x6Au, 0x31u, 0xF6u, 0xA9u, 0x8Cu, 0x42u, 0xE3u, 0xD7u,
    0x9Du, 0xEFu, 0x2Cu, 0x0Bu, 0xA1u, 0xDEu, 0xE9u, 0xBDu,
    0xB7u, 0x56u, 0x6Du, 0x6Bu, 0x56u, 0x2Cu, 0xFFu, 0x86u,
    0x28u, 0x0Eu, 0xDDu, 0x42u, 0x9Bu, 0x97u, 0xB0u, 0xA7u,
    0x18u, 0x61u, 0x1Au, 0x9Eu, 0x7Du, 0xC6u, 0x49u, 0x71u,
    0x90u, 0xDBu, 0xEFu, 0xB8u, 0x67u, 0x14u, 0x36u, 0x86u,
    0xF2u, 0xF0u, 0x71u, 0x5Au, 0x3Bu, 0x64u, 0xCAu, 0xCDu,
    0xD1u, 0x15u, 0x57u, 0xD6u, 0x73u, 0xE9u, 0x5Bu, 0x03u,
    0xFCu, 0x4Cu, 0x19u, 0x58u, 0x43u, 0xE4u, 0xC7u, 0x8Du,
    0x50u, 0x5Au, 0x34u, 0x18u, 0x41u, 0x53u, 0x33u, 0xD1u,
    0x42u, 0xDFu, 0x7Au, 0x77u, 0xF4u, 0x66u, 0xE4u, 0xE3u,
    0xB9u, 0xF6u, 0xEDu, 0x55u, 0x8Bu, 0xD6u, 0x85u, 0x7Cu,
    0x95u, 0x44u, 0xFCu, 0xC3u, 0x0Du, 0x1Fu, 0xAFu, 0x8Au,
    0x45u, 0x8Eu, 0xA9u, 0xB3u, 0xEEu, 0x48u, 0xEEu, 0xF7u,
    0x9Cu, 0xBCu, 0x26u, 0xDCu, 0x71u, 0xBFu, 0x5Bu, 0x66u,
    0x17u, 0x6Bu, 0xACu, 0xB0u, 0xE4u, 0xF8u, 0x85u, 0x2Du,
    0xB1u, 0x4Eu, 0xC7u, 0x25u, 0xADu, 0x4Au, 0x47u, 0x76u,
    0x6Du, 0x0Bu, 0xA3u, 0x01u, 0xB3u, 0xD6u, 0xE0u, 0x21u,
    0x79u, 0x18u, 0xA3u, 0x42u, 0x72u, 0x52u, 0x6Bu, 0xD2u,
    0x2Cu, 0x0Bu, 0x70u, 0xD1u, 0x5Au, 0x4Fu, 0x8Cu, 0xFBu,
};

/**
 * @brief Extended nonce used by the XChaCha20-Poly1305 tests.
 */
static const uint8_t s_aead_nonce[CRYPTO_AEAD_NONCE_LEN] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
};

/**
 * @brief Associated data used by the XChaCha20-Poly1305 tests.
 */
static const uint8_t s_ad[8] = {
    0x50u, 0x51u, 0x52u, 0x53u, 0xC0u, 0xC1u, 0xC2u, 0xC3u,
};

/**
 * @brief Tampered associated data used to reject a forged frame.
 */
static const uint8_t s_ad_bad[8] = {
    0x51u, 0x51u, 0x52u, 0x53u, 0xC0u, 0xC1u, 0xC2u, 0xC3u,
};

/**
 * @brief Sixteen-byte plaintext used by the XChaCha20-Poly1305 tests.
 */
static const uint8_t s_pt16[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

/**
 * @brief Passphrase used by the Argon2id tests.
 */
static const uint8_t s_pwd[8] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

/**
 * @brief Primary salt used by the Argon2id tests.
 */
static const uint8_t s_salt[8] = {'s', 'a', 'l', 't', 's', 'a', 'l', 't'};

/**
 * @brief Alternate salt used to prove salt sensitivity.
 */
static const uint8_t s_salt2[8] = {'s', 'a', 'l', 't', 'S', 'a', 'l', 't'};

/**
 * @brief File-scope NEC pulse-duration scratch buffer.
 */
static uint16_t s_pulses[IR_REMOTE_MAX_PULSES];

/**
 * @brief File-scope GPIO timeline offset scratch buffer for the IR eye.
 */
static uint32_t s_ir_off[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief File-scope GPIO timeline level scratch buffer for the IR eye.
 */
static int s_ir_lvl[IR_REMOTE_MAX_PULSES * 2u];

/**
 * @brief Reset the peripheral and crypto host mocks.
 *
 * @param void No parameters.
 * @return void
 */
static void reset_pc(void) {
    mock_timer_reset();
    mock_gpio_reset();
    mock_pwm_reset();
    rex_reset();
}

/**
 * @brief Assert exactly one annunciator lamp is lit.
 *
 * @param red Expected red lamp level.
 * @param yellow Expected yellow lamp level.
 * @param green Expected green lamp level.
 * @return void
 */
static void assert_lamps(int red, int yellow, int green) {
    TEST_ASSERT_EQUAL_INT(red, mock_gpio_get(ACCESS_GATE_RED_LED_PIN));
    TEST_ASSERT_EQUAL_INT(yellow,
                          mock_gpio_get(ACCESS_GATE_YELLOW_LED_PIN));
    TEST_ASSERT_EQUAL_INT(green,
                          mock_gpio_get(ACCESS_GATE_GREEN_LED_PIN));
}

/**
 * @brief Assert the recorded servo PWM level.
 *
 * @param expected Expected pulse width in microseconds.
 * @return void
 */
static void assert_servo_pulse(uint16_t expected) {
    TEST_ASSERT_EQUAL_UINT(expected,
                           mock_pwm_get_level(ACCESS_GATE_SERVO_PIN));
}

/**
 * @brief Fill the mutable Argon2 cost fields.
 *
 * @param p Pointer to the parameter block to fill.
 * @param lanes Number of parallel lanes.
 * @param mem Requested memory in 1 KiB blocks.
 * @param t Number of passes over the memory.
 * @param type Argon2 type identifier.
 * @return void
 */
static void params_fill_costs(argon2_params_t *p, uint32_t lanes, uint32_t mem,
                              uint32_t t, uint32_t type) {
    p->time_cost = t;
    p->lanes = lanes;
    p->memory_blocks = mem;
    p->tag_len = CRYPTO_KDF_KEY_LEN;
    p->type = type;
}

/**
 * @brief Clear the optional Argon2 inputs.
 *
 * @param p Pointer to the parameter block to clear.
 * @return void
 */
static void params_clear_extras(argon2_params_t *p) {
    p->secret = NULL;
    p->secret_len = 0u;
    p->ad = NULL;
    p->ad_len = 0u;
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
}

/**
 * @brief Append one timeline point and advance the entry count.
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
    for (i = 0u; i < IR_NEC_FRAME_PULSES; ++i) {
        n = nec_append(offsets, levels, n, t, (i % 2u == 0u) ? 0 : 1);
        t += pulses[i];
    }
    n = nec_append(offsets, levels, n, t, 1);
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
 * @brief Show one gate state and assert the exact lamp pattern.
 *
 * @param state Gate state to show.
 * @param red Expected red lamp level.
 * @param yellow Expected yellow lamp level.
 * @param green Expected green lamp level.
 * @return void
 */
static void assert_show(status_led_state_t state, int red, int yellow,
                        int green) {
    status_led_show(state);
    assert_lamps(red, yellow, green);
}

/**
 * @brief Verify initialization and every annunciator show state.
 *
 * @param void No parameters.
 * @return void
 */
static void test_status_led_show(void) {
    reset_pc();
    TEST_ASSERT_TRUE(status_led_init());
    assert_show(STATUS_LED_OFF, 0, 0, 0);
    assert_show(STATUS_LED_DENIED, 1, 0, 0);
    assert_show(STATUS_LED_PENDING, 0, 1, 0);
    assert_show(STATUS_LED_GRANTED, 0, 0, 1);
}

/**
 * @brief Verify the button press polarity and init.
 *
 * @param void No parameters.
 * @return void
 */
static void test_rex_pressed(void) {
    reset_pc();
    TEST_ASSERT_TRUE(rex_init());
    gpio_put(ACCESS_GATE_BUTTON_PIN, true);
    TEST_ASSERT_FALSE(rex_pressed());
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_pressed());
}

/**
 * @brief Verify press consumption returns true exactly once.
 *
 * @param void No parameters.
 * @return void
 */
static void test_rex_consume(void) {
    reset_pc();
    rex_init();
    gpio_put(ACCESS_GATE_BUTTON_PIN, true);
    TEST_ASSERT_FALSE(rex_consume_press());
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
    TEST_ASSERT_FALSE(rex_consume_press());
}

/**
 * @brief Release the button and clear its consumed latch.
 *
 * @param void No parameters.
 * @return void
 */
static void rex_release(void) {
    gpio_put(ACCESS_GATE_BUTTON_PIN, true);
    rex_consume_press();
}

/**
 * @brief Verify the debounce window suppresses a bounce.
 *
 * @param void No parameters.
 * @return void
 */
static void test_rex_debounce(void) {
    reset_pc();
    rex_init();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
    rex_release();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_FALSE(rex_consume_press());
}

/**
 * @brief Verify a press is accepted after the debounce window.
 *
 * @param void No parameters.
 * @return void
 */
static void test_rex_debounce_elapsed(void) {
    reset_pc();
    rex_init();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
    rex_release();
    mock_timer_set_us(mock_timer_now_us() + REX_DEBOUNCE_US);
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
}

/**
 * @brief Verify rex_reset clears the debounce state.
 *
 * @param void No parameters.
 * @return void
 */
static void test_rex_reset(void) {
    reset_pc();
    rex_init();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
    rex_reset();
    rex_release();
    gpio_put(ACCESS_GATE_BUTTON_PIN, false);
    TEST_ASSERT_TRUE(rex_consume_press());
}

/**
 * @brief Verify the angle-to-pulse mapping and clamping.
 *
 * @param void No parameters.
 * @return void
 */
static void test_servo_map(void) {
    reset_pc();
    TEST_ASSERT_EQUAL_UINT(SERVO_MIN_PULSE_US, servo_angle_to_pulse_us(0u));
    TEST_ASSERT_EQUAL_UINT(1500u, servo_angle_to_pulse_us(90u));
    TEST_ASSERT_EQUAL_UINT(SERVO_MAX_PULSE_US, servo_angle_to_pulse_us(180u));
    TEST_ASSERT_EQUAL_UINT(SERVO_MAX_PULSE_US, servo_angle_to_pulse_us(200u));
}

/**
 * @brief Verify the servo PWM slice configuration.
 *
 * @param void No parameters.
 * @return void
 */
static void test_servo_init(void) {
    /**
     * @brief Declaration of slice.
     */
    uint slice;
    reset_pc();
    TEST_ASSERT_TRUE(servo_init());
    slice = pwm_gpio_to_slice_num(ACCESS_GATE_SERVO_PIN);
    TEST_ASSERT_TRUE(mock_pwm_is_running(slice));
    TEST_ASSERT_EQUAL_UINT(9631u, mock_pwm_get_wrap(slice));
    TEST_ASSERT_TRUE(mock_pwm_get_clkdiv(slice) > 63.0f);
}

/**
 * @brief Verify set, unlock, and lock drive the recorded PWM level.
 *
 * @param void No parameters.
 * @return void
 */
static void test_servo_actuate(void) {
    servo_init();
    servo_set_angle(45u);
    assert_servo_pulse(servo_angle_to_pulse_us(45u));
    servo_unlock();
    assert_servo_pulse(servo_angle_to_pulse_us(SERVO_ANGLE_UNLOCKED_DEGREES));
    servo_lock();
    assert_servo_pulse(servo_angle_to_pulse_us(SERVO_ANGLE_LOCKED_DEGREES));
}

/**
 * @brief Verify the infrared receiver input configuration.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_init(void) {
    reset_pc();
    TEST_ASSERT_TRUE(ir_remote_init());
    TEST_ASSERT_FALSE(s_mock_gpio_dirs[ACCESS_GATE_IR_PIN]);
}

/**
 * @brief Verify a valid NEC frame decodes to address and command.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_valid(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    TEST_ASSERT_TRUE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
    TEST_ASSERT_TRUE(cmd.valid);
    TEST_ASSERT_EQUAL_UINT8(0x00u, cmd.address);
    TEST_ASSERT_EQUAL_UINT8(0x45u, cmd.command);
}

/**
 * @brief Verify short and null frames are rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_rejects(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES - 1u, &cmd));
    TEST_ASSERT_FALSE(ir_decode_nec(NULL, IR_NEC_FRAME_PULSES, &cmd));
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, NULL));
}

/**
 * @brief Verify an out-of-band leader mark is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_bad_leader(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    s_pulses[0] = 500u;
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
}

/**
 * @brief Verify an out-of-band bit mark is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_bad_mark(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    s_pulses[2] = 100u;
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
}

/**
 * @brief Verify an ambiguous bit space is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_ambiguous(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    s_pulses[3] = 1100u;
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
}

/**
 * @brief Verify a broken address complement is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_bad_address(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    s_pulses[19] = 560u;
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
}

/**
 * @brief Verify a broken command complement is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_decode_bad_command(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_fill(s_pulses, 0x45u);
    s_pulses[51] = 1690u;
    TEST_ASSERT_FALSE(ir_decode_nec(s_pulses, IR_NEC_FRAME_PULSES, &cmd));
}

/**
 * @brief Verify polling captures and decodes an armed frame.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_poll_valid(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    nec_arm(0x45u);
    TEST_ASSERT_TRUE(ir_remote_poll(&cmd));
    TEST_ASSERT_EQUAL_UINT8(0x45u, cmd.command);
}

/**
 * @brief Verify polling reports no frame when the line stays low.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_poll_timeout(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    TEST_ASSERT_FALSE(ir_remote_poll(&cmd));
}

/**
 * @brief Verify polling reports no frame when the line stays high.
 *
 * @param void No parameters.
 * @return void
 */
static void test_ir_poll_stuck_high(void) {
    /**
     * @brief Declaration of cmd.
     */
    ir_command_t cmd;
    reset_pc();
    gpio_put(ACCESS_GATE_IR_PIN, true);
    TEST_ASSERT_FALSE(ir_remote_poll(&cmd));
}

/**
 * @brief Verify the RFC 8439 ChaCha20 block vector.
 *
 * @param void No parameters.
 * @return void
 */
static void test_chacha20_block(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[CHACHA20_BLOCK_LEN];
    chacha20_block(s_rfc_key, 1u, s_rfc_nonce, out);
    TEST_ASSERT_EQUAL_MEMORY(s_rfc_block, out, CHACHA20_BLOCK_LEN);
}

/**
 * @brief Verify the RFC 8439 ChaCha20 stream vector.
 *
 * @param void No parameters.
 * @return void
 */
static void test_chacha20_stream(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[sizeof(s_stream_ct)];
    chacha20_xor(s_rfc_key, s_stream_nonce, 1u, s_stream_pt, out, sizeof(out));
    TEST_ASSERT_EQUAL_MEMORY(s_stream_ct, out, sizeof(out));
}

/**
 * @brief Verify the HChaCha20 subkey vector.
 *
 * @param void No parameters.
 * @return void
 */
static void test_hchacha20(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[CHACHA20_KEY_LEN];
    hchacha20(s_rfc_key, s_hchacha_nonce, out);
    TEST_ASSERT_EQUAL_MEMORY(s_hchacha_out, out, CHACHA20_KEY_LEN);
}

/**
 * @brief Verify the RFC 8439 Poly1305 tag vector.
 *
 * @param void No parameters.
 * @return void
 */
static void test_poly1305(void) {
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[POLY1305_TAG_LEN];
    poly1305_mac(s_poly_key, s_poly_msg, sizeof(s_poly_msg) - 1u, tag);
    TEST_ASSERT_EQUAL_MEMORY(s_poly_tag, tag, POLY1305_TAG_LEN);
}

/**
 * @brief Verify Poly1305 is deterministic on an aligned block.
 *
 * @param void No parameters.
 * @return void
 */
static void test_poly1305_aligned(void) {
    /**
     * @brief Declaration of first.
     */
    uint8_t first[POLY1305_TAG_LEN];
    /**
     * @brief Declaration of second.
     */
    uint8_t second[POLY1305_TAG_LEN];
    poly1305_mac(s_poly_key, s_pt16, sizeof(s_pt16), first);
    poly1305_mac(s_poly_key, s_pt16, sizeof(s_pt16), second);
    TEST_ASSERT_EQUAL_MEMORY(first, second, POLY1305_TAG_LEN);
}

/**
 * @brief Verify an XChaCha20-Poly1305 seal-open round trip.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_roundtrip(void) {
    /**
     * @brief Declaration of ct.
     */
    uint8_t ct[32];
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    /**
     * @brief Declaration of pt.
     */
    uint8_t pt[32];
    TEST_ASSERT_TRUE(crypto_aead_seal(s_rfc_key, s_aead_nonce, s_ad, 8u, s_pt16,
                                      5u, ct, tag));
    TEST_ASSERT_TRUE(crypto_aead_open(s_rfc_key, s_aead_nonce, s_ad, 8u, ct, 5u,
                                      tag, pt));
    TEST_ASSERT_EQUAL_MEMORY(s_pt16, pt, 5u);
}

/**
 * @brief Verify a round trip on aligned associated data and plaintext.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_aligned(void) {
    /**
     * @brief Declaration of ct.
     */
    uint8_t ct[32];
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    /**
     * @brief Declaration of pt.
     */
    uint8_t pt[32];
    TEST_ASSERT_TRUE(crypto_aead_seal(s_rfc_key, s_aead_nonce, s_pt16, 16u,
                                      s_pt16, 16u, ct, tag));
    TEST_ASSERT_TRUE(crypto_aead_open(s_rfc_key, s_aead_nonce, s_pt16, 16u, ct,
                                      16u, tag, pt));
    TEST_ASSERT_EQUAL_MEMORY(s_pt16, pt, 16u);
}

/**
 * @brief Verify a flipped tag is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_tamper_tag(void) {
    /**
     * @brief Declaration of ct.
     */
    uint8_t ct[32];
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    /**
     * @brief Declaration of pt.
     */
    uint8_t pt[32];
    crypto_aead_seal(s_rfc_key, s_aead_nonce, s_ad, 8u, s_pt16, 5u, ct, tag);
    tag[0] ^= 0x01u;
    TEST_ASSERT_FALSE(crypto_aead_open(s_rfc_key, s_aead_nonce, s_ad, 8u, ct,
                                       5u, tag, pt));
}

/**
 * @brief Verify flipped ciphertext is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_tamper_ct(void) {
    /**
     * @brief Declaration of ct.
     */
    uint8_t ct[32];
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    /**
     * @brief Declaration of pt.
     */
    uint8_t pt[32];
    crypto_aead_seal(s_rfc_key, s_aead_nonce, s_ad, 8u, s_pt16, 5u, ct, tag);
    ct[0] ^= 0x01u;
    TEST_ASSERT_FALSE(crypto_aead_open(s_rfc_key, s_aead_nonce, s_ad, 8u, ct,
                                       5u, tag, pt));
}

/**
 * @brief Verify mismatched associated data is rejected.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_tamper_ad(void) {
    /**
     * @brief Declaration of ct.
     */
    uint8_t ct[32];
    /**
     * @brief Declaration of tag.
     */
    uint8_t tag[CRYPTO_AEAD_TAG_LEN];
    /**
     * @brief Declaration of pt.
     */
    uint8_t pt[32];
    crypto_aead_seal(s_rfc_key, s_aead_nonce, s_ad, 8u, s_pt16, 5u, ct, tag);
    TEST_ASSERT_FALSE(crypto_aead_open(s_rfc_key, s_aead_nonce, s_ad_bad, 8u,
                                       ct, 5u, tag, pt));
}

/**
 * @brief Verify the constant-time tag comparison.
 *
 * @param void No parameters.
 * @return void
 */
static void test_aead_tag_equal(void) {
    /**
     * @brief Declaration of left.
     */
    uint8_t left[CRYPTO_AEAD_TAG_LEN] = {0u};
    /**
     * @brief Declaration of right.
     */
    uint8_t right[CRYPTO_AEAD_TAG_LEN] = {0u};
    TEST_ASSERT_TRUE(crypto_aead_tag_equal(left, right));
    right[15] = 1u;
    TEST_ASSERT_FALSE(crypto_aead_tag_equal(left, right));
}

/**
 * @brief Verify the BLAKE2b-512 digest of abc.
 *
 * @param void No parameters.
 * @return void
 */
static void test_blake2b_abc(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[BLAKE2B_OUT_LEN];
    blake2b_hash(out, BLAKE2B_OUT_LEN, (const uint8_t *)"abc", 3u);
    TEST_ASSERT_EQUAL_MEMORY(s_blake_abc, out, BLAKE2B_OUT_LEN);
}

/**
 * @brief Verify a multi-block BLAKE2b-512 digest.
 *
 * @param void No parameters.
 * @return void
 */
static void test_blake2b_multiblock(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[BLAKE2B_OUT_LEN];
    /**
     * @brief Declaration of in.
     */
    uint8_t in[200];
    memset(in, 0x5Au, sizeof(in));
    blake2b_hash(out, BLAKE2B_OUT_LEN, in, sizeof(in));
    TEST_ASSERT_EQUAL_MEMORY(s_blake_5a, out, BLAKE2B_OUT_LEN);
}

/**
 * @brief Verify the short H' branch used for a thirty-two byte tag.
 *
 * @param void No parameters.
 * @return void
 */
static void test_blake2b_long_short(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[32];
    /**
     * @brief Declaration of in.
     */
    uint8_t in[4] = {1u, 2u, 3u, 4u};
    blake2b_long(out, 32u, in, sizeof(in));
    TEST_ASSERT_EQUAL_MEMORY(s_hprime_32, out, 32u);
}

/**
 * @brief Verify the chained H' branch used for long output.
 *
 * @param void No parameters.
 * @return void
 */
static void test_blake2b_long(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[256];
    /**
     * @brief Declaration of in.
     */
    uint8_t in[4] = {1u, 2u, 3u, 4u};
    blake2b_long(out, 256u, in, sizeof(in));
    TEST_ASSERT_EQUAL_MEMORY(s_hprime_256, out, 256u);
}

/**
 * @brief Verify Argon2id argument validation.
 *
 * @param void No parameters.
 * @return void
 */
static void test_kdf_rejects(void) {
    /**
     * @brief Declaration of key.
     */
    uint8_t key[CRYPTO_KDF_KEY_LEN];
    reset_pc();
    TEST_ASSERT_FALSE(crypto_kdf_argon2id(s_pwd, sizeof(s_pwd), s_salt, 7u,
                                          key));
    TEST_ASSERT_FALSE(crypto_kdf_argon2id(NULL, sizeof(s_pwd), s_salt,
                                          CRYPTO_KDF_SALT_MIN_LEN, key));
}

/**
 * @brief Verify the empty-password branch derives a key.
 *
 * @param void No parameters.
 * @return void
 */
static void test_kdf_empty_password(void) {
    /**
     * @brief Declaration of key.
     */
    uint8_t key[CRYPTO_KDF_KEY_LEN];
    reset_pc();
    TEST_ASSERT_TRUE(crypto_kdf_argon2id(NULL, 0u, s_salt,
                                         CRYPTO_KDF_SALT_MIN_LEN, key));
}

/**
 * @brief Verify Argon2id determinism and salt sensitivity.
 *
 * @param void No parameters.
 * @return void
 */
static void test_kdf_determinism(void) {
    /**
     * @brief Declaration of first.
     */
    uint8_t first[CRYPTO_KDF_KEY_LEN];
    /**
     * @brief Declaration of second.
     */
    uint8_t second[CRYPTO_KDF_KEY_LEN];
    TEST_ASSERT_TRUE(crypto_kdf_argon2id(s_pwd, sizeof(s_pwd), s_salt, 8u, first));
    TEST_ASSERT_TRUE(crypto_kdf_argon2id(s_pwd, sizeof(s_pwd), s_salt, 8u, second));
    TEST_ASSERT_EQUAL_MEMORY(first, second, CRYPTO_KDF_KEY_LEN);
}

/**
 * @brief Verify a different salt derives a different key.
 *
 * @param void No parameters.
 * @return void
 */
static void test_kdf_salt(void) {
    /**
     * @brief Declaration of first.
     */
    uint8_t first[CRYPTO_KDF_KEY_LEN];
    /**
     * @brief Declaration of other.
     */
    uint8_t other[CRYPTO_KDF_KEY_LEN];
    TEST_ASSERT_TRUE(crypto_kdf_argon2id(s_pwd, sizeof(s_pwd), s_salt, 8u, first));
    TEST_ASSERT_TRUE(crypto_kdf_argon2id(s_pwd, sizeof(s_pwd), s_salt2, 8u, other));
    TEST_ASSERT_TRUE(memcmp(first, other, CRYPTO_KDF_KEY_LEN) != 0);
}

/**
 * @brief Verify the multi-lane Argon2 path and last-block fold.
 *
 * @param void No parameters.
 * @return void
 */
static void test_argon2_lanes(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[CRYPTO_KDF_KEY_LEN];
    /**
     * @brief Declaration of p.
     */
    argon2_params_t p;
    params_fill_costs(&p, 2u, 64u, 2u, ARGON2_TYPE_ID);
    params_clear_extras(&p);
    argon2_hash(&p, s_pwd, sizeof(s_pwd), s_salt, CRYPTO_KDF_SALT_MIN_LEN, out);
    TEST_ASSERT_TRUE(out[0] != 0u);
}

/**
 * @brief Verify the data-independent Argon2i path.
 *
 * @param void No parameters.
 * @return void
 */
static void test_argon2_type_i(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[CRYPTO_KDF_KEY_LEN];
    /**
     * @brief Declaration of p.
     */
    argon2_params_t p;
    params_fill_costs(&p, 1u, 16u, 1u, ARGON2_TYPE_I);
    params_clear_extras(&p);
    argon2_hash(&p, s_pwd, sizeof(s_pwd), s_salt, CRYPTO_KDF_SALT_MIN_LEN, out);
    TEST_ASSERT_TRUE(out[0] != 0u);
}

/**
 * @brief Verify the small-memory geometry clamp.
 *
 * @param void No parameters.
 * @return void
 */
static void test_argon2_clamp(void) {
    /**
     * @brief Declaration of out.
     */
    uint8_t out[CRYPTO_KDF_KEY_LEN];
    /**
     * @brief Declaration of p.
     */
    argon2_params_t p;
    params_fill_costs(&p, 2u, 8u, 1u, ARGON2_TYPE_ID);
    params_clear_extras(&p);
    argon2_hash(&p, s_pwd, sizeof(s_pwd), s_salt, CRYPTO_KDF_SALT_MIN_LEN, out);
    TEST_ASSERT_TRUE(out[0] != 0u);
}

/**
 * @brief Fixed 24-byte nonce for deterministic envelope vectors.
 */
static const uint8_t s_env_nonce[ENVELOPE_NONCE_LEN] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
};

/**
 * @brief Expected nonce produced by six counter-valued mock random words.
 */
static const uint8_t s_env_nonce_expect[ENVELOPE_NONCE_LEN] = {
    0x00u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u,
    0x02u, 0x00u, 0x00u, 0x00u, 0x03u, 0x00u, 0x00u, 0x00u,
    0x04u, 0x00u, 0x00u, 0x00u, 0x05u, 0x00u, 0x00u, 0x00u,
};

/**
 * @brief Canonical telemetry body sealed by the envelope tests.
 */
static const uint8_t s_env_pt[] = "{\"n\":7,\"s\":0,\"t\":230,\"h\":610}";

/**
 * @brief Single associated-data byte carrying the provisioned node identity.
 */
static const uint8_t s_env_ad = (uint8_t)PACKET_NODE_ID;

/**
 * @brief Scratch lowercase hex envelope buffer.
 */
static char s_env_hex[ENVELOPE_MAX_HEX_LEN];

/**
 * @brief Scratch recovered plaintext buffer.
 */
static uint8_t s_env_out[ENVELOPE_MAX_PLAINTEXT];

/**
 * @brief Recovered plaintext length from the most recent open.
 */
static size_t s_env_out_len;

/**
 * @brief Single-byte output buffer exercising the too-small plaintext path.
 */
static uint8_t s_env_small[1];

/**
 * @brief Known-answer hex envelope for the fixed key, nonce, and body.
 */
static const char s_env_known_hex[] = "000102030405060708090a0b0c0d0e0f1011121314151617e5e0615daae5a18c40661cfee770dcca71751b95d1f475c9452c0e8640d2cfa44e69151a7363d94a3011f0865b";

/**
 * @brief Seal the canonical body into the scratch hex envelope.
 *
 * @param void No parameters.
 * @return bool true when the envelope was sealed.
 */
static bool seal_env(void) {
    return envelope_seal_hex(s_rfc_key, s_env_nonce, &s_env_ad, 1u, s_env_pt, sizeof(s_env_pt) - 1u, s_env_hex, sizeof(s_env_hex));
}

/**
 * @brief Open the scratch hex envelope into the scratch plaintext buffer.
 *
 * @param void No parameters.
 * @return bool true when the envelope opened.
 */
static bool open_env(void) {
    return envelope_open_hex(s_rfc_key, &s_env_ad, 1u, s_env_hex, s_env_out, sizeof(s_env_out), &s_env_out_len);
}

/**
 * @brief Flip one hex nibble and assert the envelope no longer opens.
 *
 * @param pos Index of the hex character to flip.
 * @return void
 */
static void assert_open_flip(size_t pos) {
    char saved = s_env_hex[pos];
    s_env_hex[pos] = (saved == '0') ? '1' : '0';
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, s_env_hex, s_env_out, sizeof(s_env_out), &s_env_out_len));
    s_env_hex[pos] = saved;
}

/**
 * @brief Assert malformed and truncated hex inputs never open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_open_bad_hex(void) {
    TEST_ASSERT_TRUE(seal_env());
    s_env_hex[0] = 'g';
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, s_env_hex, s_env_out, sizeof(s_env_out), &s_env_out_len));
    TEST_ASSERT_TRUE(seal_env());
    s_env_hex[strlen(s_env_hex) - 1u] = '\0';
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, s_env_hex, s_env_out, sizeof(s_env_out), &s_env_out_len));
}

/**
 * @brief Assert short and oversized hex inputs never open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_open_short(void) {
    char long_hex[200];
    memset(long_hex, '0', sizeof(long_hex) - 2u);
    long_hex[sizeof(long_hex) - 2u] = '\0';
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, "00", s_env_out, sizeof(s_env_out), &s_env_out_len));
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, long_hex, s_env_out, sizeof(s_env_out), &s_env_out_len));
}

/**
 * @brief Assert an undersized plaintext buffer never opens.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_open_small(void) {
    TEST_ASSERT_TRUE(seal_env());
    TEST_ASSERT_FALSE(envelope_open_hex(s_rfc_key, &s_env_ad, 1u, s_env_hex, s_env_small, sizeof(s_env_small), &s_env_out_len));
}

/**
 * @brief Assert flipped ciphertext and tag nibbles never open.
 *
 * @param void No parameters.
 * @return void
 */
static void assert_open_tamper(void) {
    TEST_ASSERT_TRUE(seal_env());
    assert_open_flip(ENVELOPE_NONCE_LEN * 2u + 1u);
    assert_open_flip((ENVELOPE_NONCE_LEN + (sizeof(s_env_pt) - 1u)) * 2u + 1u);
}

/**
 * @brief Verify the mock random source fills the nonce word by word.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_nonce(void) {
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    mock_rand_reset();
    envelope_fill_nonce(nonce);
    TEST_ASSERT_EQUAL_MEMORY(s_env_nonce_expect, nonce, ENVELOPE_NONCE_LEN);
}

/**
 * @brief Verify a sealed envelope opens back to the original body.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_roundtrip(void) {
    TEST_ASSERT_TRUE(seal_env());
    TEST_ASSERT_TRUE(open_env());
    TEST_ASSERT_EQUAL_UINT(sizeof(s_env_pt) - 1u, (unsigned)s_env_out_len);
    TEST_ASSERT_EQUAL_MEMORY(s_env_pt, s_env_out, s_env_out_len);
}

/**
 * @brief Verify seal rejects overlong plaintext and undersized output.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_seal_rejects(void) {
    char tiny[8];
    TEST_ASSERT_FALSE(envelope_seal_hex(s_rfc_key, s_env_nonce, &s_env_ad, 1u, s_env_pt, ENVELOPE_MAX_PLAINTEXT + 1u, s_env_hex, sizeof(s_env_hex)));
    TEST_ASSERT_FALSE(envelope_seal_hex(s_rfc_key, s_env_nonce, &s_env_ad, 1u, s_env_pt, 1u, tiny, sizeof(tiny)));
}

/**
 * @brief Verify malformed, truncated, tampered, and short envelopes reject.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_open_rejects(void) {
    TEST_ASSERT_TRUE(seal_env());
    assert_open_bad_hex();
    assert_open_short();
    assert_open_small();
    assert_open_tamper();
}

/**
 * @brief Verify uppercase hex envelopes decode and open.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_uppercase(void) {
    size_t i;
    TEST_ASSERT_TRUE(seal_env());
    for (i = 0u; s_env_hex[i] != '\0'; ++i) {
        if (s_env_hex[i] >= 'a' && s_env_hex[i] <= 'f') { s_env_hex[i] = (char)(s_env_hex[i] - 'a' + 'A'); }
    }
    TEST_ASSERT_TRUE(open_env());
    TEST_ASSERT_EQUAL_MEMORY(s_env_pt, s_env_out, s_env_out_len);
}

/**
 * @brief Verify the committed known-answer envelope seals and opens.
 *
 * @param void No parameters.
 * @return void
 */
static void test_envelope_known_vector(void) {
    TEST_ASSERT_TRUE(seal_env());
    TEST_ASSERT_EQUAL_STRING(s_env_known_hex, s_env_hex);
    TEST_ASSERT_TRUE(open_env());
    TEST_ASSERT_EQUAL_MEMORY(s_env_pt, s_env_out, s_env_out_len);
}

/**
 * @brief Run the status LED and request-to-exit tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_indicator_tests(void) {
    RUN_TEST(test_status_led_show);
    RUN_TEST(test_rex_pressed);
    RUN_TEST(test_rex_consume);
    RUN_TEST(test_rex_debounce);
    RUN_TEST(test_rex_debounce_elapsed);
    RUN_TEST(test_rex_reset);
}

/**
 * @brief Run the servo actuation and infrared receiver tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_servo_ir_tests(void) {
    RUN_TEST(test_servo_map);
    RUN_TEST(test_servo_init);
    RUN_TEST(test_servo_actuate);
    RUN_TEST(test_ir_init);
    RUN_TEST(test_ir_decode_valid);
    RUN_TEST(test_ir_decode_rejects);
    RUN_TEST(test_ir_decode_bad_leader);
    RUN_TEST(test_ir_decode_bad_mark);
}

/**
 * @brief Run the remaining infrared decode and poll tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_ir_tests(void) {
    RUN_TEST(test_ir_decode_ambiguous);
    RUN_TEST(test_ir_decode_bad_address);
    RUN_TEST(test_ir_decode_bad_command);
    RUN_TEST(test_ir_poll_valid);
    RUN_TEST(test_ir_poll_timeout);
    RUN_TEST(test_ir_poll_stuck_high);
}

/**
 * @brief Run the ChaCha20 and Poly1305 vector tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_stream_tests(void) {
    RUN_TEST(test_chacha20_block);
    RUN_TEST(test_chacha20_stream);
    RUN_TEST(test_hchacha20);
    RUN_TEST(test_poly1305);
    RUN_TEST(test_poly1305_aligned);
}

/**
 * @brief Run the hex envelope codec tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_envelope_tests(void) {
    RUN_TEST(test_envelope_nonce);
    RUN_TEST(test_envelope_roundtrip);
    RUN_TEST(test_envelope_seal_rejects);
    RUN_TEST(test_envelope_open_rejects);
    RUN_TEST(test_envelope_uppercase);
    RUN_TEST(test_envelope_known_vector);
}

/**
 * @brief Run the XChaCha20-Poly1305 envelope tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_aead_tests(void) {
    RUN_TEST(test_aead_roundtrip);
    RUN_TEST(test_aead_aligned);
    RUN_TEST(test_aead_tamper_tag);
    RUN_TEST(test_aead_tamper_ct);
    RUN_TEST(test_aead_tamper_ad);
    RUN_TEST(test_aead_tag_equal);
    run_envelope_tests();
}

/**
 * @brief Run the BLAKE2b and Argon2id derivation tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_hash_kdf_tests(void) {
    RUN_TEST(test_blake2b_abc);
    RUN_TEST(test_blake2b_multiblock);
    RUN_TEST(test_blake2b_long_short);
    RUN_TEST(test_blake2b_long);
    RUN_TEST(test_kdf_rejects);
    RUN_TEST(test_kdf_empty_password);
    RUN_TEST(test_kdf_determinism);
    RUN_TEST(test_kdf_salt);
}

/**
 * @brief Run the direct Argon2 core branch tests.
 *
 * @param void No parameters.
 * @return void
 */
static void run_argon2_tests(void) {
    RUN_TEST(test_argon2_lanes);
    RUN_TEST(test_argon2_type_i);
    RUN_TEST(test_argon2_clamp);
}

void run_peripheral_and_crypto_tests(void) {
    run_indicator_tests();
    run_servo_ir_tests();
    run_ir_tests();
    run_stream_tests();
    run_aead_tests();
    run_hash_kdf_tests();
    run_argon2_tests();
}
