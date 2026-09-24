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
// File:    harness.h
// Desc:    Minimal in-repo test harness API replacing the vendored framework.
// Created: 2026

#ifndef HARNESS_H
#define HARNESS_H

#include <stddef.h>

/**
 * @brief Test setup hook executed before each test case.
 *
 * @param void No parameters.
 * @return void
 */
void setUp(void);

/**
 * @brief Test teardown hook executed after each test case.
 *
 * @param void No parameters.
 * @return void
 */
void tearDown(void);

/**
 * @brief Initialize the runner counters.
 *
 * @param void No parameters.
 * @return void
 */
void harness_begin(void);

/**
 * @brief Print the run summary and return the failure count.
 *
 * @param void No parameters.
 * @return int Number of failed checks.
 */
int harness_finish(void);

/**
 * @brief Run one test case with setup, teardown, and failure isolation.
 *
 * @param name Test case name.
 * @param fn Test case function pointer.
 * @return void
 */
void harness_run(const char *name, void (*fn)(void));

/**
 * @brief Record and report a failing boolean-true check.
 *
 * @param ok Nonzero when the check passed.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_true(int ok, const char *file, int line);

/**
 * @brief Record and report a failing boolean-false check.
 *
 * @param ok Nonzero when the negated check passed.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_false(int ok, const char *file, int line);

/**
 * @brief Record and report a failing signed integer comparison.
 *
 * @param expected Expected value.
 * @param actual Actual value.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_int(long expected, long actual, const char *file, int line);

/**
 * @brief Record and report a failing unsigned integer comparison.
 *
 * @param expected Expected value.
 * @param actual Actual value.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_uint(unsigned long expected, unsigned long actual,
                       const char *file, int line);

/**
 * @brief Record and report a failing string comparison.
 *
 * @param expected Expected string.
 * @param actual Actual string.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_str(const char *expected, const char *actual, const char *file,
                      int line);

/**
 * @brief Record and report a failing memory comparison.
 *
 * @param expected Expected buffer.
 * @param actual Actual buffer.
 * @param len Number of bytes to compare.
 * @param file Source file of the check.
 * @param line Source line of the check.
 * @return void
 */
void harness_assert_mem(const void *expected, const void *actual, size_t len,
                      const char *file, int line);

/**
 * @brief Open a harness test run.
 */
#define TEST_BEGIN() harness_begin()

/**
 * @brief Close a harness test run and return the failure count.
 */
#define TEST_END() harness_finish()

/**
 * @brief Register and run one test case by name.
 */
#define RUN_TEST(fn) harness_run(#fn, fn)

/**
 * @brief Assert that a condition is nonzero.
 */
#define TEST_ASSERT(cond) \
    harness_assert_true((cond) ? 1 : 0, __FILE__, __LINE__)

/**
 * @brief Assert that a condition is nonzero.
 */
#define TEST_ASSERT_TRUE(cond) \
    harness_assert_true((cond) ? 1 : 0, __FILE__, __LINE__)

/**
 * @brief Assert that a condition is zero.
 */
#define TEST_ASSERT_FALSE(cond) \
    harness_assert_false((cond) ? 1 : 0, __FILE__, __LINE__)

/**
 * @brief Assert two signed integers are equal.
 */
#define TEST_ASSERT_EQUAL(a, b) \
    harness_assert_int((long)(a), (long)(b), __FILE__, __LINE__)

/**
 * @brief Assert two signed integers are equal.
 */
#define TEST_ASSERT_EQUAL_INT(a, b) \
    harness_assert_int((long)(a), (long)(b), __FILE__, __LINE__)

/**
 * @brief Assert two unsigned integers are equal.
 */
#define TEST_ASSERT_EQUAL_UINT(a, b) \
    harness_assert_uint((unsigned long)(a), (unsigned long)(b), __FILE__, __LINE__)

/**
 * @brief Assert two unsigned 8-bit integers are equal.
 */
#define TEST_ASSERT_EQUAL_UINT8(a, b) \
    harness_assert_uint((unsigned long)(a), (unsigned long)(b), __FILE__, __LINE__)

/**
 * @brief Assert two unsigned 16-bit integers are equal.
 */
#define TEST_ASSERT_EQUAL_HEX16(a, b) \
    harness_assert_uint((unsigned long)(a), (unsigned long)(b), __FILE__, __LINE__)

/**
 * @brief Assert two NUL-terminated strings are equal.
 */
#define TEST_ASSERT_EQUAL_STRING(a, b) \
    harness_assert_str((a), (b), __FILE__, __LINE__)

/**
 * @brief Assert two memory regions are equal.
 */
#define TEST_ASSERT_EQUAL_MEMORY(a, b, n) \
    harness_assert_mem((a), (b), (n), __FILE__, __LINE__)

#endif // HARNESS_H
