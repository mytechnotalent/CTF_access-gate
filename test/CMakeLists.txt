# MIT License
#
# Copyright (c) 2026 Kevin Thomas
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Author:  Kevin Thomas
# Email:   kevin@mytechnotalent.com
# GitHub:  https://github.com/mytechnotalent/cold-chain-monitor-c-rp2350
# File:    CMakeLists.txt
# Desc:    CMake configuration for native host unit testing with the in-repo harness.
# Created: 2026

cmake_minimum_required(VERSION 3.13)
project(access_gate_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(test_access_gate_and_security
    harness/harness.c
    test_access_gate_and_security.c
    test_peripheral_and_crypto.c
)

target_include_directories(test_access_gate_and_security PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/mock
    ${CMAKE_CURRENT_SOURCE_DIR}/harness
)

target_compile_options(test_access_gate_and_security PRIVATE -fcommon)

enable_testing()
add_test(NAME test_access_gate_and_security COMMAND test_access_gate_and_security)
