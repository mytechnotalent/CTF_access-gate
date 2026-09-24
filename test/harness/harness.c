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
// File:    harness.c
// Desc:    Minimal in-repo test harness implementation replacing the vendored
//          framework with a strictly C-standard-compliant runner.
// Created: 2026

#include "harness.h"
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Longjmp target used to abandon a failing test case.
 */
static jmp_buf g_jmp;

/**
 * @brief Number of failed checks in the current run.
 */
static int g_failures;

/**
 * @brief Number of checks executed in the current run.
 */
static int g_checks;

/**
 * @brief Name of the currently running test case.
 */
static const char *g_case;

/**
 * @brief Record a failure, report it, and abandon the current test case.
 *
 * @param file Source file of the failing check.
 * @param line Source line of the failing check.
 * @param msg Short failure description.
 * @return void
 */
static void harness_fail(const char *file, int line, const char *msg) {
    g_failures += 1;
    printf("%s:%d:%s:FAIL:%s\n", file, line, g_case, msg);
    longjmp(g_jmp, 1);
}

void harness_begin(void) {
    g_failures = 0;
    g_checks = 0;
}

int harness_finish(void) {
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures;
}

void harness_run(const char *name, void (*fn)(void)) {
    g_case = name;
    if (setjmp(g_jmp) == 0) {
        setUp();
        fn();
        tearDown();
        printf(":%s:PASS\n", name);
    } else {
        printf(":%s:FAIL\n", name);
    }
}

void harness_assert_true(int ok, const char *file, int line) {
    g_checks += 1;
    if (!ok) harness_fail(file, line, "expected true");
}

void harness_assert_false(int ok, const char *file, int line) {
    g_checks += 1;
    if (ok) harness_fail(file, line, "expected false");
}

void harness_assert_int(long expected, long actual, const char *file, int line) {
    g_checks += 1;
    if (expected != actual) harness_fail(file, line, "int mismatch");
}

void harness_assert_uint(unsigned long expected, unsigned long actual,
                       const char *file, int line) {
    g_checks += 1;
    if (expected != actual) harness_fail(file, line, "uint mismatch");
}

void harness_assert_str(const char *expected, const char *actual, const char *file,
                      int line) {
    g_checks += 1;
    if ((expected == NULL) || (actual == NULL) || (strcmp(expected, actual) != 0)) {
        harness_fail(file, line, "string mismatch");
    }
}

void harness_assert_mem(const void *expected, const void *actual, size_t len,
                      const char *file, int line) {
    g_checks += 1;
    if ((expected == NULL) || (actual == NULL) || (memcmp(expected, actual, len) != 0)) {
        harness_fail(file, line, "memory mismatch");
    }
}
