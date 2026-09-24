#!/usr/bin/env python3
"""Pure-Python XChaCha20-Poly1305 AEAD and Argon2id key derivation.

This module implements the OPERATION COLD IRON field profile with only the
Python standard library. It derives the shared field key with RFC 9106
Argon2id and seals or opens compact telemetry frames with XChaCha20-Poly1305
using the node identifier as associated data. The byte layout interoperates
with the RP2350 firmware implemented under src/.
"""

import hashlib
import hmac
import secrets

CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = (1 << 128) - 1
POLY_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
POLY_MODULUS = (1 << 130) - 5
BLOCK_LEN = 64
ARGON2_BLOCK_WORDS = 128
ADDRESSES_IN_BLOCK = 128
SYNC_POINTS = 4
ARGON2_VERSION = 0x13
ARGON2_TYPE_I = 1
ARGON2_TYPE_ID = 2
XCHACHA_NONCE_LEN = 24
AEAD_TAG_LEN = 16
FIELD_PASSWORD = b"operation cold iron field key v1"
FIELD_SALT = b"coldiron-salt-01"
FIELD_TIME_COST = 3
FIELD_MEMORY_BLOCKS = 64
FIELD_PARALLELISM = 1
FIELD_TAG_LEN = 32
FIELD_AD = bytes([7])
_FIELD_KEY = None


def _rotl32(value, count):
    """Rotate a 32-bit word to the left.

    Parameters
    ----------
    value : int
        Word to rotate.
    count : int
        Rotation distance in bits.

    Returns
    -------
    int
        Rotated word masked to 32 bits.
    """
    shifted = (value << count) & MASK32
    return shifted | (value >> (32 - count))


def _quarter_round(state, a, b, c, d):
    """Apply one ChaCha20 quarter round in place.

    Parameters
    ----------
    state : list of int
        Sixteen-word ChaCha20 state.
    a : int
        First word index.
    b : int
        Second word index.
    c : int
        Third word index.
    d : int
        Fourth word index.

    Returns
    -------
    None
    """
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _little_words(data, size):
    """Split bytes into little-endian words of a fixed width.

    Parameters
    ----------
    data : bytes
        Byte string to split.
    size : int
        Width of each word in bytes.

    Returns
    -------
    list of int
        Little-endian words.
    """
    return [int.from_bytes(data[i:i + size], "little")
            for i in range(0, len(data), size)]


def _word_bytes(words, size):
    """Join integers into little-endian byte words.

    Parameters
    ----------
    words : iterable of int
        Word values to encode.
    size : int
        Width of each word in bytes.

    Returns
    -------
    bytes
        Encoded little-endian byte string.
    """
    return b"".join(word.to_bytes(size, "little") for word in words)


def _block_words(data):
    """Load a 1024-byte block into 128 little-endian words.

    Parameters
    ----------
    data : bytes
        Block bytes to load.

    Returns
    -------
    list of int
        One hundred twenty-eight 64-bit words.
    """
    return _little_words(data, 8)


def _block_bytes(words):
    """Store 128 little-endian words as a 1024-byte block.

    Parameters
    ----------
    words : iterable of int
        Block words to store.

    Returns
    -------
    bytes
        Serialized 1024-byte block.
    """
    return _word_bytes(words, 8)


def _le32(value):
    """Encode a 32-bit integer as four little-endian bytes.

    Parameters
    ----------
    value : int
        Value to encode.

    Returns
    -------
    bytes
        Four little-endian bytes.
    """
    return value.to_bytes(4, "little")


def _le64(value):
    """Encode a 64-bit integer as eight little-endian bytes.

    Parameters
    ----------
    value : int
        Value to encode.

    Returns
    -------
    bytes
        Eight little-endian bytes.
    """
    return value.to_bytes(8, "little")


def _length_blob(data):
    """Prefix a byte field with its little-endian 32-bit length.

    Parameters
    ----------
    data : bytes
        Field bytes to prefix.

    Returns
    -------
    bytes
        Length prefix followed by the field bytes.
    """
    return _le32(len(data)) + data


def _chacha_state(key, counter, nonce):
    """Build the sixteen-word ChaCha20 state.

    Parameters
    ----------
    key : bytes
        Thirty-two byte ChaCha20 key.
    counter : int
        Block counter for the state.
    nonce : bytes
        Twelve-byte IETF nonce.

    Returns
    -------
    list of int
        Sixteen-word ChaCha20 state.
    """
    state = list(CHACHA_CONSTANTS)
    state += _little_words(key, 4)
    state.append(counter & MASK32)
    return state + _little_words(nonce, 4)


def _chacha_double_round(state):
    """Apply the ChaCha20 column and diagonal quarter rounds.

    Parameters
    ----------
    state : list of int
        Sixteen-word ChaCha20 state.

    Returns
    -------
    None
    """
    _quarter_round(state, 0, 4, 8, 12)
    _quarter_round(state, 1, 5, 9, 13)
    _quarter_round(state, 2, 6, 10, 14)
    _quarter_round(state, 3, 7, 11, 15)
    _quarter_round(state, 0, 5, 10, 15)
    _quarter_round(state, 1, 6, 11, 12)
    _quarter_round(state, 2, 7, 8, 13)
    _quarter_round(state, 3, 4, 9, 14)


def _chacha_rounds(state):
    """Apply the twenty ChaCha20 rounds in place.

    Parameters
    ----------
    state : list of int
        Sixteen-word ChaCha20 state.

    Returns
    -------
    None
    """
    for _ in range(10):
        _chacha_double_round(state)


def _chacha20_block(key, counter, nonce):
    """Generate one ChaCha20 keystream block.

    Parameters
    ----------
    key : bytes
        Thirty-two byte ChaCha20 key.
    counter : int
        Block counter for the keystream.
    nonce : bytes
        Twelve-byte IETF nonce.

    Returns
    -------
    bytes
        Sixty-four byte keystream block.
    """
    state = _chacha_state(key, counter, nonce)
    working = list(state)
    _chacha_rounds(working)
    words = [(working[i] + state[i]) & MASK32 for i in range(16)]
    return _word_bytes(words, 4)


def _xor_bytes(left, right):
    """XOR two byte strings pairwise.

    Parameters
    ----------
    left : bytes
        First byte string.
    right : bytes
        Second byte string.

    Returns
    -------
    bytes
        XORed bytes of the shorter length.
    """
    return bytes(x ^ y for x, y in zip(left, right))


def _chacha20_xor(key, counter, nonce, data):
    """Encrypt or decrypt bytes with the ChaCha20 stream.

    Parameters
    ----------
    key : bytes
        Thirty-two byte ChaCha20 key.
    counter : int
        Initial block counter.
    nonce : bytes
        Twelve-byte IETF nonce.
    data : bytes
        Input bytes to process.

    Returns
    -------
    bytes
        Output bytes of the same length as the input.
    """
    output = bytearray()
    for offset in range(0, len(data), BLOCK_LEN):
        block = _chacha20_block(key, counter + offset // BLOCK_LEN, nonce)
        output += _xor_bytes(data[offset:offset + BLOCK_LEN], block)
    return bytes(output)


def _hchacha20(key, nonce):
    """Derive a 32-byte HChaCha20 subkey from a 16-byte nonce.

    Parameters
    ----------
    key : bytes
        Thirty-two byte ChaCha20 key.
    nonce : bytes
        Sixteen-byte extended nonce.

    Returns
    -------
    bytes
        Thirty-two byte subkey.
    """
    working = list(CHACHA_CONSTANTS) + _little_words(key, 4)
    working += _little_words(nonce, 4)
    _chacha_rounds(working)
    return _word_bytes(working[:4] + working[12:16], 4)


def _poly_block(chunk):
    """Encode one Poly1305 message block with its high bit.

    Parameters
    ----------
    chunk : bytes
        Message chunk of up to sixteen bytes.

    Returns
    -------
    int
        Integer value of the chunk plus a trailing one bit.
    """
    return int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))


def _poly1305_mac(one_time_key, message):
    """Compute a Poly1305 tag over a message.

    Parameters
    ----------
    one_time_key : bytes
        Thirty-two byte one-time key.
    message : bytes
        Message bytes to authenticate.

    Returns
    -------
    bytes
        Sixteen byte Poly1305 tag.
    """
    acc = 0
    r = int.from_bytes(one_time_key[:16], "little") & POLY_CLAMP
    for offset in range(0, len(message), 16):
        acc = ((acc + _poly_block(message[offset:offset + 16])) * r)
        acc %= POLY_MODULUS
    acc = (acc + int.from_bytes(one_time_key[16:32], "little")) & MASK128
    return acc.to_bytes(16, "little")


def _pad16(data):
    """Pad bytes to a sixteen-byte boundary with zeros.

    Parameters
    ----------
    data : bytes
        Bytes to pad.

    Returns
    -------
    bytes
        Zero padding only when the length is not a multiple of sixteen.
    """
    return data + b"\x00" * (-len(data) % 16)


def _aead_tag_input(aad, ciphertext):
    """Build the Poly1305 input for an AEAD frame.

    Parameters
    ----------
    aad : bytes
        Associated data authenticated but not encrypted.
    ciphertext : bytes
        Ciphertext bytes to authenticate.

    Returns
    -------
    bytes
        Padded associated data, ciphertext, and both lengths.
    """
    body = _pad16(aad) + _pad16(ciphertext)
    return body + _le64(len(aad)) + _le64(len(ciphertext))


def _ietf_nonce(nonce):
    """Build the IETF nonce from the extended nonce tail.

    Parameters
    ----------
    nonce : bytes
        Twenty-four byte extended nonce.

    Returns
    -------
    bytes
        Twelve-byte IETF nonce.
    """
    return b"\x00\x00\x00\x00" + nonce[16:24]


def _xchacha_seal(key, nonce, aad, plaintext):
    """Seal plaintext with XChaCha20-Poly1305.

    Parameters
    ----------
    key : bytes
        Thirty-two byte symmetric key.
    nonce : bytes
        Twenty-four byte nonce.
    aad : bytes
        Associated data authenticated but not encrypted.
    plaintext : bytes
        Plaintext bytes to encrypt.

    Returns
    -------
    tuple of bytes
        Ciphertext and sixteen-byte authentication tag.
    """
    subkey = _hchacha20(key, nonce[:16])
    ietf = _ietf_nonce(nonce)
    otk = _chacha20_block(subkey, 0, ietf)[:32]
    ciphertext = _chacha20_xor(subkey, 1, ietf, plaintext)
    tag = _poly1305_mac(otk, _aead_tag_input(aad, ciphertext))
    return ciphertext, tag


def _xchacha_open(key, nonce, aad, ciphertext, tag):
    """Open an XChaCha20-Poly1305 frame after verifying its tag.

    Parameters
    ----------
    key : bytes
        Thirty-two byte symmetric key.
    nonce : bytes
        Twenty-four byte nonce.
    aad : bytes
        Associated data authenticated but not encrypted.
    ciphertext : bytes
        Ciphertext bytes to decrypt.
    tag : bytes
        Sixteen byte authentication tag.

    Returns
    -------
    bytes
        Recovered plaintext bytes.

    Raises
    ------
    ValueError
        When the tag does not authenticate the frame.
    """
    subkey = _hchacha20(key, nonce[:16])
    ietf = _ietf_nonce(nonce)
    otk = _chacha20_block(subkey, 0, ietf)[:32]
    expected = _poly1305_mac(otk, _aead_tag_input(aad, ciphertext))
    if not hmac.compare_digest(expected, tag):
        raise ValueError("field frame failed authentication")
    return _chacha20_xor(subkey, 1, ietf, ciphertext)


def _blamka(left, right):
    """Apply the Argon2 BLAMKA addition.

    Parameters
    ----------
    left : int
        First addend.
    right : int
        Second addend.

    Returns
    -------
    int
        Combined value masked to 64 bits.
    """
    product = 2 * (left & MASK32) * (right & MASK32)
    return (left + right + product) & MASK64


def _rotr64(value, count):
    """Rotate a 64-bit word to the right.

    Parameters
    ----------
    value : int
        Word to rotate.
    count : int
        Rotation distance in bits.

    Returns
    -------
    int
        Rotated word masked to 64 bits.
    """
    return ((value >> count) | (value << (64 - count))) & MASK64


def _blamka_g(words, a, b, c, d):
    """Apply the BLAMKA G mixing function to four words.

    Parameters
    ----------
    words : list of int
        Mutable Argon2 block words.
    a : int
        First word index.
    b : int
        Second word index.
    c : int
        Third word index.
    d : int
        Fourth word index.

    Returns
    -------
    None
    """
    words[a] = _blamka(words[a], words[b])
    words[d] = _rotr64(words[d] ^ words[a], 32)
    words[c] = _blamka(words[c], words[d])
    words[b] = _rotr64(words[b] ^ words[c], 24)
    words[a] = _blamka(words[a], words[b])
    words[d] = _rotr64(words[d] ^ words[a], 16)
    words[c] = _blamka(words[c], words[d])
    words[b] = _rotr64(words[b] ^ words[c], 63)


def _blamka_round(words, offset):
    """Apply one BLAKE2b round to a contiguous word group.

    Parameters
    ----------
    words : list of int
        Mutable Argon2 block words.
    offset : int
        Offset of the first word of the group.

    Returns
    -------
    None
    """
    _blamka_g(words, offset, offset + 4, offset + 8, offset + 12)
    _blamka_g(words, offset + 1, offset + 5, offset + 9, offset + 13)
    _blamka_g(words, offset + 2, offset + 6, offset + 10, offset + 14)
    _blamka_g(words, offset + 3, offset + 7, offset + 11, offset + 15)
    _blamka_g(words, offset, offset + 5, offset + 10, offset + 15)
    _blamka_g(words, offset + 1, offset + 6, offset + 11, offset + 12)
    _blamka_g(words, offset + 2, offset + 7, offset + 8, offset + 13)
    _blamka_g(words, offset + 3, offset + 4, offset + 9, offset + 14)


def _blamka_row_round(words, base):
    """Apply one BLAKE2b round to a strided row group.

    Parameters
    ----------
    words : list of int
        Mutable Argon2 block words.
    base : int
        Offset of the first two words of the row.

    Returns
    -------
    None
    """
    _blamka_g(words, base, base + 32, base + 64, base + 96)
    _blamka_g(words, base + 1, base + 33, base + 65, base + 97)
    _blamka_g(words, base + 16, base + 48, base + 80, base + 112)
    _blamka_g(words, base + 17, base + 49, base + 81, base + 113)
    _blamka_g(words, base, base + 33, base + 80, base + 113)
    _blamka_g(words, base + 1, base + 48, base + 81, base + 96)
    _blamka_g(words, base + 16, base + 49, base + 64, base + 97)
    _blamka_g(words, base + 17, base + 32, base + 65, base + 112)


def _permute(words):
    """Apply the Argon2 permutation to one block in place.

    Parameters
    ----------
    words : list of int
        Mutable Argon2 block words.

    Returns
    -------
    None
    """
    for index in range(8):
        _blamka_round(words, 16 * index)
    for index in range(8):
        _blamka_row_round(words, 2 * index)


def _compress(previous, reference, current=None, with_xor=False):
    """Apply the Argon2 compression function G.

    Parameters
    ----------
    previous : list of int
        Previous block words.
    reference : list of int
        Reference block words.
    current : list of int or None
        Existing target block used only when with_xor is set.
    with_xor : bool
        True to XOR the result with the existing target block.

    Returns
    -------
    list of int
        Newly compressed block words.
    """
    mixed = [x ^ y for x, y in zip(reference, previous)]
    temporary = list(mixed)
    if with_xor:
        temporary = [x ^ y for x, y in zip(temporary, current)]
    _permute(mixed)
    return [x ^ y for x, y in zip(temporary, mixed)]


def _address_block(zero, source, counter):
    """Generate one data-independent Argon2 address block.

    Parameters
    ----------
    zero : list of int
        All-zero block.
    source : list of int
        Mutable addressing input block.
    counter : int
        One-based address block counter.

    Returns
    -------
    list of int
        Generated address block words.
    """
    source[6] = counter
    return _compress(zero, _compress(zero, source))


def _h_prime_prefix(seed, rounds):
    """Build the chained 32-byte prefixes of the Argon2 H' hash.

    Parameters
    ----------
    seed : bytes
        Length-prefixed input seed.
    rounds : int
        Number of sixty-four byte chaining blocks.

    Returns
    -------
    tuple
        Concatenated prefixes and the final full block.
    """
    block = hashlib.blake2b(seed, digest_size=64).digest()
    output = bytearray()
    for _ in range(rounds - 1):
        output += block[:32]
        block = hashlib.blake2b(block, digest_size=64).digest()
    output += block[:32]
    return bytes(output), block


def _h_prime_long(seed, out_len):
    """Hash a seed to more than sixty-four bytes with Argon2 H'.

    Parameters
    ----------
    seed : bytes
        Length-prefixed input seed.
    out_len : int
        Requested output length in bytes.

    Returns
    -------
    bytes
        Variable-length hash output.
    """
    rounds = -(-out_len // 32) - 2
    prefix, last = _h_prime_prefix(seed, rounds)
    tail_len = out_len - 32 * rounds
    tail = hashlib.blake2b(last, digest_size=tail_len).digest()
    return prefix + tail


def _h_prime(data, out_len):
    """Hash data to a variable length with Argon2 H'.

    Parameters
    ----------
    data : bytes
        Input bytes to hash.
    out_len : int
        Requested output length in bytes.

    Returns
    -------
    bytes
        Variable-length hash output.
    """
    seed = _le32(out_len) + data
    if out_len <= 64:
        return hashlib.blake2b(seed, digest_size=out_len).digest()
    return _h_prime_long(seed, out_len)


def _argon2_h0(password, salt, time_cost, memory_blocks, lanes, tag_len,
               type_id, secret, ad):
    """Compute the Argon2 pre-hashing digest H0.

    Parameters
    ----------
    password : bytes
        Password bytes.
    salt : bytes
        Salt bytes.
    time_cost : int
        Number of passes.
    memory_blocks : int
        Requested memory in one KiB blocks.
    lanes : int
        Number of parallel lanes.
    tag_len : int
        Requested tag length in bytes.
    type_id : int
        Argon2 type identifier.
    secret : bytes
        Optional secret key bytes.
    ad : bytes
        Optional associated data bytes.

    Returns
    -------
    bytes
        Sixty-four byte H0 digest.
    """
    fields = [lanes, tag_len, memory_blocks, time_cost, ARGON2_VERSION,
              type_id]
    header = b"".join(_le32(value) for value in fields)
    body = b"".join(_length_blob(item) for item in
                    (password, salt, secret, ad))
    return hashlib.blake2b(header + body, digest_size=64).digest()


def _lane_seed(h0, index, lane):
    """Derive the 1024-byte seed for one of a lane's first two blocks.

    Parameters
    ----------
    h0 : bytes
        Sixty-four byte pre-hashing digest.
    index : int
        Block index inside the lane, either zero or one.
    lane : int
        Lane index.

    Returns
    -------
    bytes
        Variable-length hash output for the block seed.
    """
    return _h_prime(h0 + _le32(index) + _le32(lane), 1024)


def _argon2_init(h0, total, lanes):
    """Fill the first two blocks of every Argon2 lane.

    Parameters
    ----------
    h0 : bytes
        Sixty-four byte pre-hashing digest.
    total : int
        Rounded total memory block count.
    lanes : int
        Number of parallel lanes.

    Returns
    -------
    list
        Memory matrix with the first two blocks of each lane set.
    """
    lane_length = total // lanes
    memory = [None] * total
    for lane in range(lanes):
        base = lane * lane_length
        memory[base] = _block_words(_lane_seed(h0, 0, lane))
        memory[base + 1] = _block_words(_lane_seed(h0, 1, lane))
    return memory


def _address_input(pass_index, lane, slice_index, total, passes, type_id):
    """Build the Argon2 data-independent addressing input block.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    lane : int
        Current lane index.
    slice_index : int
        Current slice index.
    total : int
        Rounded total memory block count.
    passes : int
        Total number of passes.
    type_id : int
        Argon2 type identifier.

    Returns
    -------
    list of int
        One hundred twenty-eight addressing input words.
    """
    header = [pass_index, lane, slice_index, total, passes, type_id, 0]
    return header + [0] * (ARGON2_BLOCK_WORDS - len(header))


def _segment_addresses(info, segment):
    """Generate the data-independent pseudo-random values for a segment.

    Parameters
    ----------
    info : tuple
        Segment identity and geometry values.
    segment : int
        Number of blocks in the segment.

    Returns
    -------
    list of int
        Pseudo-random values indexed by segment position.
    """
    zero = [0] * ARGON2_BLOCK_WORDS
    source = _address_input(*info[:6])
    count = -(-segment // ADDRESSES_IN_BLOCK)
    blocks = [_address_block(zero, source, index + 1)
              for index in range(count)]
    values = []
    for block in blocks:
        values += block
    return values


def _uses_independent(pass_index, slice_index, type_id):
    """Report whether a segment uses data-independent addressing.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    slice_index : int
        Current slice index.
    type_id : int
        Argon2 type identifier.

    Returns
    -------
    bool
        True when the segment uses data-independent addressing.
    """
    if type_id == ARGON2_TYPE_I:
        return True
    return type_id == ARGON2_TYPE_ID and pass_index == 0 and slice_index < 2


def _area_first(slice_index, index, segment, same_lane):
    """Compute the reference area size during the first pass.

    Parameters
    ----------
    slice_index : int
        Current slice index.
    index : int
        Block index inside the segment.
    segment : int
        Number of blocks in the segment.
    same_lane : bool
        True when the reference lane equals the current lane.

    Returns
    -------
    int
        Number of referenceable blocks.
    """
    if slice_index == 0:
        return index - 1
    if same_lane:
        return slice_index * segment + index - 1
    return slice_index * segment + (-1 if index == 0 else 0)


def _area_later(index, lane_length, segment, same_lane):
    """Compute the reference area size during later passes.

    Parameters
    ----------
    index : int
        Block index inside the segment.
    lane_length : int
        Number of blocks in one lane.
    segment : int
        Number of blocks in the segment.
    same_lane : bool
        True when the reference lane equals the current lane.

    Returns
    -------
    int
        Number of referenceable blocks.
    """
    if same_lane:
        return lane_length - segment + index - 1
    return lane_length - segment + (-1 if index == 0 else 0)


def _reference_area(pass_index, slice_index, index, lane_length, segment,
                    same_lane):
    """Compute the Argon2 reference area size for the current pass.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    slice_index : int
        Current slice index.
    index : int
        Block index inside the segment.
    lane_length : int
        Number of blocks in one lane.
    segment : int
        Number of blocks in the segment.
    same_lane : bool
        True when the reference lane equals the current lane.

    Returns
    -------
    int
        Number of referenceable blocks.
    """
    if pass_index == 0:
        return _area_first(slice_index, index, segment, same_lane)
    return _area_later(index, lane_length, segment, same_lane)


def _pass_start(slice_index, segment):
    """Compute the first referenceable column offset of a pass.

    Parameters
    ----------
    slice_index : int
        Current slice index.
    segment : int
        Number of blocks in the segment.

    Returns
    -------
    int
        First referenceable column offset.
    """
    if slice_index == SYNC_POINTS - 1:
        return 0
    return (slice_index + 1) * segment


def _index_alpha(pass_index, slice_index, index, pseudo, lane_length,
                 segment, same_lane):
    """Map a pseudo-random value onto a reference column index.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    slice_index : int
        Current slice index.
    index : int
        Block index inside the segment.
    pseudo : int
        Latest pseudo-random value.
    lane_length : int
        Number of blocks in one lane.
    segment : int
        Number of blocks in the segment.
    same_lane : bool
        True when the reference lane equals the current lane.

    Returns
    -------
    int
        Reference column index inside the reference lane.
    """
    area = _reference_area(pass_index, slice_index, index, lane_length,
                           segment, same_lane)
    relative = pseudo & MASK32
    relative = (relative * relative) >> 32
    relative = (area - 1) - ((area * relative) >> 32)
    start = 0 if pass_index == 0 else _pass_start(slice_index, segment)
    return (start + relative) % lane_length


def _reference_lane(pass_index, slice_index, pseudo, lanes, lane):
    """Resolve the reference lane for the current block.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    slice_index : int
        Current slice index.
    pseudo : int
        Latest pseudo-random value.
    lanes : int
        Number of parallel lanes.
    lane : int
        Current lane index.

    Returns
    -------
    int
        Reference lane index.
    """
    if pass_index == 0 and slice_index == 0:
        return lane
    return (pseudo >> 32) % lanes


def _reference_index(pass_index, slice_index, index, pseudo, lane_length,
                     segment, lanes, lane):
    """Resolve the absolute reference block index.

    Parameters
    ----------
    pass_index : int
        Current pass index.
    slice_index : int
        Current slice index.
    index : int
        Block index inside the segment.
    pseudo : int
        Latest pseudo-random value.
    lane_length : int
        Number of blocks in one lane.
    segment : int
        Number of blocks in the segment.
    lanes : int
        Number of parallel lanes.
    lane : int
        Current lane index.

    Returns
    -------
    int
        Absolute reference block index.
    """
    ref_lane = _reference_lane(pass_index, slice_index, pseudo, lanes, lane)
    column = _index_alpha(pass_index, slice_index, index, pseudo,
                          lane_length, segment, ref_lane == lane)
    return ref_lane * lane_length + column


def _previous_offset(current, lane_length):
    """Resolve the previous block offset within a lane.

    Parameters
    ----------
    current : int
        Absolute offset of the current block.
    lane_length : int
        Number of blocks in one lane.

    Returns
    -------
    int
        Absolute offset of the previous block.
    """
    if current % lane_length == 0:
        return current + lane_length - 1
    return current - 1


def _pseudo_value(memory, independent, randoms, index, previous):
    """Select the pseudo-random value driving block selection.

    Parameters
    ----------
    memory : list
        Argon2 memory matrix.
    independent : bool
        True when addressing is data independent.
    randoms : list of int or None
        Precomputed data-independent values.
    index : int
        Block index inside the segment.
    previous : int
        Absolute offset of the previous block.

    Returns
    -------
    int
        Latest pseudo-random value.
    """
    if independent:
        return randoms[index]
    return memory[previous][0]


def _fill_column(memory, info, segment, independent, randoms, index,
                 current):
    """Compute and store one Argon2 block.

    Parameters
    ----------
    memory : list
        Argon2 memory matrix.
    info : tuple
        Segment identity and geometry values.
    segment : int
        Number of blocks in the segment.
    independent : bool
        True when addressing is data independent.
    randoms : list of int or None
        Precomputed data-independent values.
    index : int
        Block index inside the segment.
    current : int
        Absolute offset of the current block.

    Returns
    -------
    None
    """
    pass_index, lane, slice_index, total, passes, type_id, lanes = info
    lane_length = segment * SYNC_POINTS
    previous = _previous_offset(current, lane_length)
    pseudo = _pseudo_value(memory, independent, randoms, index, previous)
    ref = _reference_index(pass_index, slice_index, index, pseudo,
                           lane_length, segment, lanes, lane)
    memory[current] = _compress(memory[previous], memory[ref],
                                memory[current], pass_index != 0)


def _fill_segment(memory, info, segment):
    """Compute every block of one Argon2 segment.

    Parameters
    ----------
    memory : list
        Argon2 memory matrix.
    info : tuple
        Segment identity and geometry values.
    segment : int
        Number of blocks in the segment.

    Returns
    -------
    None
    """
    pass_index, lane, slice_index, total, passes, type_id, lanes = info
    independent = _uses_independent(pass_index, slice_index, type_id)
    randoms = _segment_addresses(info, segment) if independent else None
    start = 2 if pass_index == 0 and slice_index == 0 else 0
    base = lane * (segment * SYNC_POINTS) + slice_index * segment
    for index in range(start, segment):
        _fill_column(memory, info, segment, independent, randoms, index,
                     base + index)


def _argon2_fill(memory, total, passes, lanes, type_id):
    """Compute the whole Argon2 memory matrix.

    Parameters
    ----------
    memory : list
        Argon2 memory matrix.
    total : int
        Rounded total memory block count.
    passes : int
        Number of passes over the memory.
    lanes : int
        Number of parallel lanes.
    type_id : int
        Argon2 type identifier.

    Returns
    -------
    None
    """
    segment = total // (lanes * SYNC_POINTS)
    for pass_index in range(passes):
        for slice_index in range(SYNC_POINTS):
            for lane in range(lanes):
                info = (pass_index, lane, slice_index, total, passes,
                        type_id, lanes)
                _fill_segment(memory, info, segment)


def _argon2_fold(memory, total, lanes):
    """XOR the last block of every lane into one final block.

    Parameters
    ----------
    memory : list
        Argon2 memory matrix.
    total : int
        Rounded total memory block count.
    lanes : int
        Number of parallel lanes.

    Returns
    -------
    bytes
        Serialized 1024-byte final block.
    """
    lane_length = total // lanes
    last = list(memory[lane_length - 1])
    for lane in range(1, lanes):
        block = memory[lane * lane_length + lane_length - 1]
        last = [x ^ y for x, y in zip(last, block)]
    return _block_bytes(last)


def _argon2id(password, salt, time_cost, memory_blocks, parallelism, tag_len,
              type_id, secret=b"", ad=b""):
    """Derive a tag with the RFC 9106 Argon2id or related type.

    Parameters
    ----------
    password : bytes
        Password bytes.
    salt : bytes
        Salt bytes.
    time_cost : int
        Number of passes over the memory.
    memory_blocks : int
        Requested memory in one KiB blocks.
    parallelism : int
        Number of parallel lanes.
    tag_len : int
        Requested tag length in bytes.
    type_id : int
        Argon2 type identifier.
    secret : bytes
        Optional secret key bytes.
    ad : bytes
        Optional associated data bytes.

    Returns
    -------
    bytes
        Derived tag bytes.
    """
    lanes = max(parallelism, 1)
    total = max(memory_blocks, 8 * lanes)
    total = total - total % (SYNC_POINTS * lanes)
    h0 = _argon2_h0(password, salt, time_cost, memory_blocks, lanes,
                    tag_len, type_id, secret, ad)
    memory = _argon2_init(h0, total, lanes)
    _argon2_fill(memory, total, time_cost, lanes, type_id)
    folded = _argon2_fold(memory, total, lanes)
    return _h_prime(folded, tag_len)


def derive_field_key():
    """Derive and cache the OPERATION COLD IRON field key.

    Parameters
    ----------
    None

    Returns
    -------
    bytes
        Cached thirty-two byte Argon2id field key.
    """
    global _FIELD_KEY
    if _FIELD_KEY is None:
        _FIELD_KEY = _argon2id(FIELD_PASSWORD, FIELD_SALT, FIELD_TIME_COST,
                               FIELD_MEMORY_BLOCKS, FIELD_PARALLELISM,
                               FIELD_TAG_LEN, ARGON2_TYPE_ID)
    return _FIELD_KEY


def seal_field_frame(plaintext):
    """Seal a telemetry frame into a lowercase hex envelope.

    Parameters
    ----------
    plaintext : bytes
        Compact JSON telemetry body to seal.

    Returns
    -------
    str
        Lowercase hex of nonce, ciphertext, and tag.
    """
    nonce = secrets.token_bytes(XCHACHA_NONCE_LEN)
    ciphertext, tag = _xchacha_seal(derive_field_key(), nonce, FIELD_AD,
                                    plaintext)
    return (nonce + ciphertext + tag).hex()


def _hex_bytes(text):
    """Decode a lowercase hex field frame, rejecting malformed input.

    Parameters
    ----------
    text : str
        Candidate hexadecimal envelope.

    Returns
    -------
    bytes
        Decoded envelope bytes.

    Raises
    ------
    ValueError
        When the text is not valid hexadecimal.
    """
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("field frame is not valid hex") from exc


def _decode_envelope(hex_payload):
    """Split a hex envelope into nonce, ciphertext, and tag.

    Parameters
    ----------
    hex_payload : str
        Lowercase hex nonce, ciphertext, and tag.

    Returns
    -------
    tuple of bytes
        Nonce, ciphertext, and tag byte strings.

    Raises
    ------
    ValueError
        When the envelope is shorter than the authentication overhead.
    """
    raw = _hex_bytes(hex_payload)
    if len(raw) < XCHACHA_NONCE_LEN + AEAD_TAG_LEN:
        raise ValueError("field frame is too short")
    nonce = raw[:XCHACHA_NONCE_LEN]
    return nonce, raw[XCHACHA_NONCE_LEN:-AEAD_TAG_LEN], raw[-AEAD_TAG_LEN:]


def open_field_frame(hex_payload):
    """Authenticate and open a lowercase hex telemetry envelope.

    Parameters
    ----------
    hex_payload : str
        Lowercase hex nonce, ciphertext, and tag.

    Returns
    -------
    bytes
        Recovered plaintext bytes.

    Raises
    ------
    ValueError
        When the frame is malformed or fails authentication.
    """
    nonce, ciphertext, tag = _decode_envelope(hex_payload)
    return _xchacha_open(derive_field_key(), nonce, FIELD_AD, ciphertext,
                         tag)
