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
// File:    argon2.c
// Desc:    Implements the RFC 9106 Argon2id core with BLAMKA compression.
// Created: 2026

#include "argon2.h"

#include "blake2b.h"
#include "crypto_kdf.h"

/**
 * @brief Static pool of Argon2 memory blocks for the classroom profile.
 */
static uint64_t g_ar2_memory[CRYPTO_KDF_MEMORY_BLOCKS * ARGON2_WORDS_IN_BLOCK];

/**
 * @brief Number of lanes currently being computed.
 */
static uint32_t g_ar2_lanes;

/**
 * @brief Rounded number of memory blocks currently allocated.
 */
static uint32_t g_ar2_memory_blocks;

/**
 * @brief Number of blocks in one lane.
 */
static uint32_t g_ar2_lane_length;

/**
 * @brief Number of blocks in one slice of a lane.
 */
static uint32_t g_ar2_segment_length;

/**
 * @brief Number of passes currently being computed.
 */
static uint32_t g_ar2_passes;

/**
 * @brief Argon2 type currently being computed.
 */
static uint32_t g_ar2_type;

/**
 * @brief The 64-byte pre-hashing digest H0.
 */
static uint8_t g_ar2_h0[BLAKE2B_OUT_LEN];

/**
 * @brief Scratch buffer holding one 1024-byte block as bytes.
 */
static uint8_t g_ar2_block_bytes[ARGON2_BLOCK_LEN];

/**
 * @brief Seed buffer holding H0 followed by two 32-bit indices.
 */
static uint8_t g_ar2_seed[BLAKE2B_OUT_LEN + 8u];

/**
 * @brief Compression scratch holding R = prev XOR ref.
 */
static uint64_t g_ar2_r[ARGON2_WORDS_IN_BLOCK];

/**
 * @brief Compression scratch holding the pre-permutation copy of R.
 */
static uint64_t g_ar2_tmp[ARGON2_WORDS_IN_BLOCK];

/**
 * @brief Data-independent address block.
 */
static uint64_t g_ar2_addr[ARGON2_WORDS_IN_BLOCK];

/**
 * @brief Data-independent addressing input block.
 */
static uint64_t g_ar2_input[ARGON2_WORDS_IN_BLOCK];

/**
 * @brief All-zero block used by the addressing compression.
 */
static uint64_t g_ar2_zero[ARGON2_WORDS_IN_BLOCK];

/**
 * @brief Pass index of the active segment.
 */
static uint32_t g_ar2_pass;

/**
 * @brief Lane index of the active segment.
 */
static uint32_t g_ar2_lane;

/**
 * @brief Slice index of the active segment.
 */
static uint32_t g_ar2_slice;

/**
 * @brief First block index computed inside the active segment.
 */
static uint32_t g_ar2_start_index;

/**
 * @brief Absolute block offset of the block being written.
 */
static uint32_t g_ar2_curr_offset;

/**
 * @brief Absolute block offset of the previous block.
 */
static uint32_t g_ar2_prev_offset;

/**
 * @brief Latest 64-bit pseudo-random value driving block selection.
 */
static uint64_t g_ar2_pseudo_rand;

/**
 * @brief Store a 32-bit little-endian integer.
 *
 * @param p Pointer to four writable bytes.
 * @param x Value to store.
 * @return void
 */
static void ar2_store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8u);
    p[2] = (uint8_t)(x >> 16u);
    p[3] = (uint8_t)(x >> 24u);
}

/**
 * @brief Store a 64-bit little-endian integer.
 *
 * @param p Pointer to eight writable bytes.
 * @param x Value to store.
 * @return void
 */
static void ar2_store_le64(uint8_t *p, uint64_t x) {
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[i] = (uint8_t)(x >> (8u * i));
    }
}

/**
 * @brief Load a 64-bit little-endian integer.
 *
 * @param p Pointer to eight readable bytes.
 * @return uint64_t Loaded value.
 */
static uint64_t ar2_load_le64(const uint8_t *p) {
    uint64_t x = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        x |= (uint64_t)p[i] << (8u * i);
    }
    return x;
}

/**
 * @brief Copy a byte range.
 *
 * @param dst Pointer to the destination bytes.
 * @param src Pointer to the source bytes.
 * @param len Number of bytes to copy.
 * @return void
 */
static void ar2_copy(uint8_t *dst, const uint8_t *src, uint32_t len) {
    uint32_t i;
    for (i = 0u; i < len; ++i) {
        dst[i] = src[i];
    }
}

/**
 * @brief Clear a full Argon2 block of words to zero.
 *
 * @param v Pointer to the block to clear.
 * @return void
 */
static void ar2_clear_words(uint64_t *v) {
    uint32_t i;
    for (i = 0u; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        v[i] = 0u;
    }
}

/**
 * @brief Copy a full Argon2 block of words.
 *
 * @param dst Pointer to the destination block.
 * @param src Pointer to the source block.
 * @return void
 */
static void ar2_copy_words(uint64_t *dst, const uint64_t *src) {
    uint32_t i;
    for (i = 0u; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        dst[i] = src[i];
    }
}

/**
 * @brief XOR two full Argon2 blocks of words.
 *
 * @param dst Pointer to the destination block.
 * @param a Pointer to the first source block.
 * @param b Pointer to the second source block.
 * @return void
 */
static void ar2_xor_words(uint64_t *dst, const uint64_t *a, const uint64_t *b) {
    uint32_t i;
    for (i = 0u; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        dst[i] = a[i] ^ b[i];
    }
}

/**
 * @brief Load one 1024-byte block into 128 little-endian words.
 *
 * @param dst Pointer to the word destination block.
 * @param bytes Pointer to the 1024 readable block bytes.
 * @return void
 */
static void ar2_load_block(uint64_t *dst, const uint8_t *bytes) {
    uint32_t i;
    for (i = 0u; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        dst[i] = ar2_load_le64(bytes + 8u * i);
    }
}

/**
 * @brief Store one 1024-byte block from 128 little-endian words.
 *
 * @param bytes Pointer to the 1024 writable block bytes.
 * @param src Pointer to the word source block.
 * @return void
 */
static void ar2_store_block(uint8_t *bytes, const uint64_t *src) {
    uint32_t i;
    for (i = 0u; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        ar2_store_le64(bytes + 8u * i, src[i]);
    }
}

/**
 * @brief Return a pointer to one block of the static memory pool.
 *
 * @param index Absolute block index inside the pool.
 * @return uint64_t * Pointer to the block words.
 */
static uint64_t *ar2_block_at(uint32_t index) {
    return g_ar2_memory + (size_t)index * ARGON2_WORDS_IN_BLOCK;
}

/**
 * @brief Apply the BLAMKA addition with a 64-bit multiply.
 *
 * @param x First addend.
 * @param y Second addend.
 * @return uint64_t Combined value.
 */
static uint64_t ar2_blamka(uint64_t x, uint64_t y) {
    return x + y + 2u * (uint64_t)(uint32_t)x * (uint32_t)y;
}

/**
 * @brief Rotate a 64-bit word to the right.
 *
 * @param x Word to rotate.
 * @param n Rotation distance in bits.
 * @return uint64_t Rotated word.
 */
static uint64_t ar2_rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64u - n));
}

/**
 * @brief Apply the BLAMKA G function to four words of a block.
 *
 * @param v Pointer to the block words.
 * @param a Index of the first word.
 * @param b Index of the second word.
 * @param c Index of the third word.
 * @param d Index of the fourth word.
 * @return void
 */
static void ar2_g(uint64_t *v, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    v[a] = ar2_blamka(v[a], v[b]);
    v[d] = ar2_rotr64(v[d] ^ v[a], 32u);
    v[c] = ar2_blamka(v[c], v[d]);
    v[b] = ar2_rotr64(v[b] ^ v[c], 24u);
    v[a] = ar2_blamka(v[a], v[b]);
    v[d] = ar2_rotr64(v[d] ^ v[a], 16u);
    v[c] = ar2_blamka(v[c], v[d]);
    v[b] = ar2_rotr64(v[b] ^ v[c], 63u);
}

/**
 * @brief Apply one 16-word BLAKE2b round to a contiguous word group.
 *
 * @param v Pointer to the block words.
 * @param o Offset of the first word of the group.
 * @return void
 */
static void ar2_round16(uint64_t *v, uint32_t o) {
    ar2_g(v, o, o + 4u, o + 8u, o + 12u);
    ar2_g(v, o + 1u, o + 5u, o + 9u, o + 13u);
    ar2_g(v, o + 2u, o + 6u, o + 10u, o + 14u);
    ar2_g(v, o + 3u, o + 7u, o + 11u, o + 15u);
    ar2_g(v, o, o + 5u, o + 10u, o + 15u);
    ar2_g(v, o + 1u, o + 6u, o + 11u, o + 12u);
    ar2_g(v, o + 2u, o + 7u, o + 8u, o + 13u);
    ar2_g(v, o + 3u, o + 4u, o + 9u, o + 14u);
}

/**
 * @brief Apply one 16-word BLAKE2b round to a strided row group.
 *
 * @param v Pointer to the block words.
 * @param j Offset of the first two words of the row.
 * @return void
 */
static void ar2_row_round(uint64_t *v, uint32_t j) {
    ar2_g(v, j, j + 32u, j + 64u, j + 96u);
    ar2_g(v, j + 1u, j + 33u, j + 65u, j + 97u);
    ar2_g(v, j + 16u, j + 48u, j + 80u, j + 112u);
    ar2_g(v, j + 17u, j + 49u, j + 81u, j + 113u);
    ar2_g(v, j, j + 33u, j + 80u, j + 113u);
    ar2_g(v, j + 1u, j + 48u, j + 81u, j + 96u);
    ar2_g(v, j + 16u, j + 49u, j + 64u, j + 97u);
    ar2_g(v, j + 17u, j + 32u, j + 65u, j + 112u);
}

/**
 * @brief Apply the Argon2 permutation P to one block.
 *
 * @param v Pointer to the block words.
 * @return void
 */
static void ar2_permute(uint64_t *v) {
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        ar2_round16(v, 16u * i);
    }
    for (i = 0u; i < 8u; ++i) {
        ar2_row_round(v, 2u * i);
    }
}

/**
 * @brief Compute the compression function G into a target block.
 *
 * @param prev Pointer to the previous block.
 * @param ref Pointer to the reference block.
 * @param next Pointer to the target block.
 * @param with_xor True to XOR the new block with the old block value.
 * @return void
 */
static void ar2_fill_block(const uint64_t *prev, const uint64_t *ref,
                           uint64_t *next, bool with_xor) {
    ar2_xor_words(g_ar2_r, ref, prev);
    ar2_copy_words(g_ar2_tmp, g_ar2_r);
    if (with_xor) {
        ar2_xor_words(g_ar2_tmp, g_ar2_tmp, next);
    }
    ar2_permute(g_ar2_r);
    ar2_xor_words(next, g_ar2_tmp, g_ar2_r);
}

/**
 * @brief Generate the next data-independent address block.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_next_addresses(void) {
    g_ar2_input[6] += 1u;
    ar2_fill_block(g_ar2_zero, g_ar2_input, g_ar2_addr, false);
    ar2_fill_block(g_ar2_zero, g_ar2_addr, g_ar2_addr, false);
}

/**
 * @brief Report whether the active segment uses data-independent addressing.
 *
 * @param void No parameters.
 * @return bool true when addressing is data independent.
 */
static bool ar2_independent(void) {
    if (g_ar2_type == ARGON2_TYPE_I) {
        return true;
    }
    return (g_ar2_type == ARGON2_TYPE_ID) && (g_ar2_pass == 0u) &&
           (g_ar2_slice < 2u);
}

/**
 * @brief Build the addressing input block for the active segment.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_init_address_input(void) {
    ar2_clear_words(g_ar2_zero);
    ar2_clear_words(g_ar2_input);
    g_ar2_input[0] = g_ar2_pass;
    g_ar2_input[1] = g_ar2_lane;
    g_ar2_input[2] = g_ar2_slice;
    g_ar2_input[3] = g_ar2_memory_blocks;
    g_ar2_input[4] = g_ar2_passes;
    g_ar2_input[5] = g_ar2_type;
}

/**
 * @brief Derive the first computed block index of the active segment.
 *
 * @param void No parameters.
 * @return uint32_t First block index to compute.
 */
static uint32_t ar2_start_index(void) {
    if ((g_ar2_pass != 0u) || (g_ar2_slice != 0u)) {
        return 0u;
    }
    if (ar2_independent()) {
        ar2_next_addresses();
    }
    return 2u;
}

/**
 * @brief Add the slice offset and start index to a lane base offset.
 *
 * @param base Lane base block offset.
 * @return uint32_t Absolute first block offset of the segment.
 */
static uint32_t ar2_segment_offset(uint32_t base) {
    return base + g_ar2_slice * g_ar2_segment_length + g_ar2_start_index;
}

/**
 * @brief Derive the block offset preceding a given offset within a lane.
 *
 * @param curr Absolute offset of the current block.
 * @return uint32_t Absolute offset of the previous block.
 */
static uint32_t ar2_prev_of(uint32_t curr) {
    if (curr % g_ar2_lane_length == 0u) {
        return curr + g_ar2_lane_length - 1u;
    }
    return curr - 1u;
}

/**
 * @brief Set up offsets and addressing for the active segment.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_segment_begin(void) {
    g_ar2_start_index = ar2_start_index();
    g_ar2_curr_offset =
        ar2_segment_offset(g_ar2_lane * g_ar2_lane_length);
    g_ar2_prev_offset = ar2_prev_of(g_ar2_curr_offset);
}

/**
 * @brief Compute the first referenceable block offset of a pass.
 *
 * @param void No parameters.
 * @return uint32_t Absolute offset of the pass start.
 */
static uint32_t ar2_pass_start(void) {
    if (g_ar2_slice == ARGON2_SYNC_POINTS - 1u) {
        return 0u;
    }
    return (g_ar2_slice + 1u) * g_ar2_segment_length;
}

/**
 * @brief Compute the reference area size during the first pass.
 *
 * @param i Index of the current block inside its segment.
 * @param same_lane True when the reference lane equals the current lane.
 * @return uint32_t Number of referenceable blocks.
 */
static uint32_t ar2_ref_area0(uint32_t i, bool same_lane) {
    if (g_ar2_slice == 0u) {
        return i - 1u;
    }
    if (same_lane) {
        return g_ar2_slice * g_ar2_segment_length + i - 1u;
    }
    return g_ar2_slice * g_ar2_segment_length +
           ((i == 0u) ? 0xFFFFFFFFu : 0u);
}

/**
 * @brief Compute the reference area size during later passes.
 *
 * @param i Index of the current block inside its segment.
 * @param same_lane True when the reference lane equals the current lane.
 * @return uint32_t Number of referenceable blocks.
 */
static uint32_t ar2_ref_area1(uint32_t i, bool same_lane) {
    if (same_lane) {
        return g_ar2_lane_length - g_ar2_segment_length + i - 1u;
    }
    return g_ar2_lane_length - g_ar2_segment_length +
           ((i == 0u) ? 0xFFFFFFFFu : 0u);
}

/**
 * @brief Compute the reference area size for the current pass.
 *
 * @param i Index of the current block inside its segment.
 * @param same_lane True when the reference lane equals the current lane.
 * @return uint32_t Number of referenceable blocks.
 */
static uint32_t ar2_ref_area(uint32_t i, bool same_lane) {
    if (g_ar2_pass == 0u) {
        return ar2_ref_area0(i, same_lane);
    }
    return ar2_ref_area1(i, same_lane);
}

/**
 * @brief Map a pseudo-random value onto a reference block index.
 *
 * @param i Index of the current block inside its segment.
 * @param pseudo_rand Latest pseudo-random value.
 * @param same_lane True when the reference lane equals the current lane.
 * @return uint32_t Absolute block index inside the reference lane.
 */
static uint32_t ar2_index_alpha(uint32_t i, uint64_t pseudo_rand,
                                bool same_lane) {
    uint32_t area = ar2_ref_area(i, same_lane);
    uint32_t start = (g_ar2_pass == 0u) ? 0u : ar2_pass_start();
    uint64_t rel = pseudo_rand & 0xFFFFFFFFu;
    rel = (rel * rel) >> 32u;
    rel = (uint64_t)(area - 1u) - (((uint64_t)area * rel) >> 32u);
    return (uint32_t)((start + (uint32_t)rel) % g_ar2_lane_length);
}

/**
 * @brief Produce the pseudo-random value driving block selection.
 *
 * @param i Index of the current block inside its segment.
 * @return uint64_t Next pseudo-random value.
 */
static uint64_t ar2_pseudo_random(uint32_t i) {
    if (ar2_independent()) {
        if (i % ARGON2_ADDRESSES_IN_BLOCK == 0u) {
            ar2_next_addresses();
        }
        return g_ar2_addr[i % ARGON2_ADDRESSES_IN_BLOCK];
    }
    return ar2_block_at(g_ar2_prev_offset)[0];
}

/**
 * @brief Resolve the absolute reference block index for the current block.
 *
 * @param i Index of the current block inside its segment.
 * @return uint32_t Absolute reference block index.
 */
static uint32_t ar2_reference_index(uint32_t i) {
    uint32_t ref_lane = (uint32_t)((g_ar2_pseudo_rand >> 32u) % g_ar2_lanes);
    bool same_lane = (ref_lane == g_ar2_lane);
    if ((g_ar2_pass == 0u) && (g_ar2_slice == 0u)) {
        ref_lane = g_ar2_lane;
        same_lane = true;
    }
    return ref_lane * g_ar2_lane_length +
           ar2_index_alpha(i, g_ar2_pseudo_rand, same_lane);
}

/**
 * @brief Compute and store the current block of the active segment.
 *
 * @param i Index of the current block inside its segment.
 * @return void
 */
static void ar2_step_block(uint32_t i) {
    uint64_t *prev = ar2_block_at(g_ar2_prev_offset);
    uint64_t *ref = ar2_block_at(ar2_reference_index(i));
    uint64_t *curr = ar2_block_at(g_ar2_curr_offset);
    ar2_fill_block(prev, ref, curr, g_ar2_pass != 0u);
}

/**
 * @brief Correct the previous offset when entering a new lane.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_adjust_prev(void) {
    if (g_ar2_curr_offset % g_ar2_lane_length == 1u) {
        g_ar2_prev_offset = g_ar2_curr_offset - 1u;
    }
}

/**
 * @brief Advance the active segment by one block.
 *
 * @param i Index of the current block inside its segment.
 * @return void
 */
static void ar2_segment_step(uint32_t i) {
    ar2_adjust_prev();
    g_ar2_pseudo_rand = ar2_pseudo_random(i);
    ar2_step_block(i);
    g_ar2_curr_offset += 1u;
    g_ar2_prev_offset += 1u;
}

/**
 * @brief Compute every block of the active segment.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_segment_run(void) {
    uint32_t i;
    for (i = g_ar2_start_index; i < g_ar2_segment_length; ++i) {
        ar2_segment_step(i);
    }
}

/**
 * @brief Compute one segment of one lane.
 *
 * @param pass Pass index.
 * @param lane Lane index.
 * @param slice Slice index.
 * @return void
 */
static void ar2_fill_segment(uint32_t pass, uint32_t lane, uint32_t slice) {
    g_ar2_pass = pass;
    g_ar2_lane = lane;
    g_ar2_slice = slice;
    if (ar2_independent()) {
        ar2_init_address_input();
    }
    ar2_segment_begin();
    ar2_segment_run();
}

/**
 * @brief Compute the whole memory matrix slice by slice.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_fill_memory(void) {
    uint32_t pass;
    uint32_t slice;
    uint32_t lane;
    for (pass = 0u; pass < g_ar2_passes; ++pass) {
        for (slice = 0u; slice < ARGON2_SYNC_POINTS; ++slice) {
            for (lane = 0u; lane < g_ar2_lanes; ++lane) {
                ar2_fill_segment(pass, lane, slice);
            }
        }
    }
}

/**
 * @brief Store a 32-bit length prefix and absorb it into the H0 state.
 *
 * @param ctx Pointer to the H0 streaming state.
 * @param value Value to absorb as four little-endian bytes.
 * @return void
 */
static void ar2_h0_u32(blake2b_ctx_t *ctx, uint32_t value) {
    uint8_t buf[4];
    ar2_store_le32(buf, value);
    blake2b_update(ctx, buf, 4u);
}

/**
 * @brief Absorb a length-prefixed byte field into the H0 state.
 *
 * @param ctx Pointer to the H0 streaming state.
 * @param data Pointer to the field bytes, or NULL when empty.
 * @param len Number of field bytes.
 * @return void
 */
static void ar2_h0_bytes(blake2b_ctx_t *ctx, const uint8_t *data,
                         uint32_t len) {
    ar2_h0_u32(ctx, len);
    if (len > 0u) {
        blake2b_update(ctx, data, len);
    }
}

/**
 * @brief Absorb the six 32-bit H0 header fields.
 *
 * @param ctx Pointer to the H0 streaming state.
 * @param p Pointer to the parameters.
 * @return void
 */
static void ar2_h0_header(blake2b_ctx_t *ctx, const argon2_params_t *p) {
    ar2_h0_u32(ctx, p->lanes);
    ar2_h0_u32(ctx, p->tag_len);
    ar2_h0_u32(ctx, p->memory_blocks);
    ar2_h0_u32(ctx, p->time_cost);
    ar2_h0_u32(ctx, ARGON2_VERSION);
    ar2_h0_u32(ctx, p->type);
}

/**
 * @brief Absorb the four variable length H0 input fields.
 *
 * @param ctx Pointer to the H0 streaming state.
 * @param p Pointer to the parameters.
 * @param pwd Pointer to the password bytes.
 * @param pwd_len Number of password bytes.
 * @param salt Pointer to the salt bytes.
 * @param salt_len Number of salt bytes.
 * @return void
 */
static void ar2_h0_body(blake2b_ctx_t *ctx, const argon2_params_t *p,
                        const uint8_t *pwd, uint32_t pwd_len,
                        const uint8_t *salt, uint32_t salt_len) {
    ar2_h0_bytes(ctx, pwd, pwd_len);
    ar2_h0_bytes(ctx, salt, salt_len);
    ar2_h0_bytes(ctx, p->secret, p->secret_len);
    ar2_h0_bytes(ctx, p->ad, p->ad_len);
}

/**
 * @brief Compute the 64-byte pre-hashing digest H0.
 *
 * @param p Pointer to the parameters.
 * @param pwd Pointer to the password bytes.
 * @param pwd_len Number of password bytes.
 * @param salt Pointer to the salt bytes.
 * @param salt_len Number of salt bytes.
 * @return void
 */
static void ar2_h0(const argon2_params_t *p, const uint8_t *pwd,
                   uint32_t pwd_len, const uint8_t *salt, uint32_t salt_len) {
    blake2b_ctx_t ctx;
    blake2b_init(&ctx, BLAKE2B_OUT_LEN);
    ar2_h0_header(&ctx, p);
    ar2_h0_body(&ctx, p, pwd, pwd_len, salt, salt_len);
    blake2b_final(&ctx, g_ar2_h0);
}

/**
 * @brief Fill one of the first two blocks of a lane.
 *
 * @param lane Lane index.
 * @param index Block index inside the lane, either 0 or 1.
 * @return void
 */
static void ar2_fill_first_block(uint32_t lane, uint32_t index) {
    ar2_copy(g_ar2_seed, g_ar2_h0, BLAKE2B_OUT_LEN);
    ar2_store_le32(g_ar2_seed + 64u, index);
    ar2_store_le32(g_ar2_seed + 68u, lane);
    blake2b_long(g_ar2_block_bytes, ARGON2_BLOCK_LEN, g_ar2_seed, 72u);
    ar2_load_block(ar2_block_at(lane * g_ar2_lane_length + index),
                   g_ar2_block_bytes);
}

/**
 * @brief Fill the first two blocks of every lane.
 *
 * @param void No parameters.
 * @return void
 */
static void ar2_fill_first_blocks(void) {
    uint32_t lane;
    for (lane = 0u; lane < g_ar2_lanes; ++lane) {
        ar2_fill_first_block(lane, 0u);
        ar2_fill_first_block(lane, 1u);
    }
}

/**
 * @brief Derive the rounded memory geometry from the parameters.
 *
 * @param p Pointer to the parameters.
 * @return void
 */
static void ar2_set_geometry(const argon2_params_t *p) {
    g_ar2_lanes = p->lanes;
    g_ar2_passes = p->time_cost;
    g_ar2_type = p->type;
    g_ar2_memory_blocks = p->memory_blocks - (p->memory_blocks % (4u * p->lanes));
    if (g_ar2_memory_blocks < 8u * p->lanes) {
        g_ar2_memory_blocks = 8u * p->lanes;
    }
    g_ar2_lane_length = g_ar2_memory_blocks / p->lanes;
    g_ar2_segment_length = g_ar2_lane_length / ARGON2_SYNC_POINTS;
}

/**
 * @brief Return a pointer to the last block of one lane.
 *
 * @param lane Lane index.
 * @return uint64_t * Pointer to the last block words of the lane.
 */
static uint64_t *ar2_lane_last(uint32_t lane) {
    return ar2_block_at(lane * g_ar2_lane_length + g_ar2_lane_length - 1u);
}

/**
 * @brief XOR the last blocks of all lanes and hash them into the tag.
 *
 * @param out Pointer to the tag output buffer.
 * @param tag_len Tag length in bytes.
 * @return void
 */
static void ar2_finalize(uint8_t *out, uint32_t tag_len) {
    uint64_t *last = ar2_lane_last(0u);
    uint32_t lane;
    for (lane = 1u; lane < g_ar2_lanes; ++lane) {
        ar2_xor_words(last, last, ar2_lane_last(lane));
    }
    ar2_store_block(g_ar2_block_bytes, last);
    blake2b_long(out, tag_len, g_ar2_block_bytes, ARGON2_BLOCK_LEN);
}

void argon2_hash(const argon2_params_t *params, const uint8_t *password,
                 uint32_t password_len, const uint8_t *salt,
                 uint32_t salt_len, uint8_t *out) {
    ar2_set_geometry(params);
    ar2_h0(params, password, password_len, salt, salt_len);
    ar2_fill_first_blocks();
    ar2_fill_memory();
    ar2_finalize(out, params->tag_len);
}
