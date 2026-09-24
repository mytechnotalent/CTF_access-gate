#!/usr/bin/env python3
"""Access Gate security desk that answers sealed unlock requests.

The desk reads +RCV frames arriving on the instructor USB-to-TTL radio.
Every payload is treated as a lowercase hex XChaCha20-Poly1305 envelope
authenticated with the gate node identifier byte 0x07. An authenticated
request is decrypted to recover the badge PIN, logged, and answered with a
sealed grant carrying a monotonic sequence number and an authenticated
state tag over the resulting authorization record. The tag is computed
with the field key, so a forged grant cannot be produced without it, and
the sequence window means a captured grant cannot be replayed.

The CSV log has the columns utc, sender, auth, pin, rssi_snr. The auth
column is OK for an authenticated request and UNAUTHENTICATED for a
rejected frame. The pin column holds the recovered PIN for an
authenticated request and an empty string for a rejected frame, so no
forged badge ever enters the log as truth.
"""

import argparse
import csv
import datetime
import itertools
import sys
import time

import field_crypto

try:
    import serial
except ImportError as exc:
    raise SystemExit(
        "pip install pyserial to run the ACCESS_GATE security desk"
    ) from exc

CSV_HEADER = ("utc", "sender", "auth", "pin", "rssi_snr")
HUB_ADDRESS = 1
RADIO_NETWORK_ID = 18
STATE_NONCE_DOMAIN = 0xA6
STATE_NONCE_LEN = 24
GRANT_FLAG = 1
PENDING_FLAG = 0
_SEQ = itertools.count(1)
_FIELD_KEY = None


def _parse_args():
    """Parse security desk command-line arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.Namespace
        Parsed security desk arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port device")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Radio baud rate")
    parser.add_argument("--log", default="access_log.csv",
                        help="CSV log destination")
    return parser.parse_args()


def _open_serial(port, baud):
    """Open the radio serial port with a short read timeout.

    Parameters
    ----------
    port : str
        Serial port device path.
    baud : int
        Radio baud rate.

    Returns
    -------
    serial.Serial
        Open radio serial connection.
    """
    return serial.Serial(port, baud, timeout=1.0)


def _provision_radio(ser):
    """Program the desk radio address and network so gates can target it.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.

    Returns
    -------
    None
    """
    for command in (f"AT+ADDRESS={HUB_ADDRESS}",
                    f"AT+NETWORKID={RADIO_NETWORK_ID}"):
        ser.write(f"{command}\r\n".encode("utf-8"))
        ser.flush()
        time.sleep(0.2)
        while True:
            raw = ser.readline()
            if not raw:
                break
            print(raw.decode("utf-8", errors="replace").strip(), flush=True)


def _read_line(ser):
    """Read one raw CRLF-terminated radio line.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.

    Returns
    -------
    str or None
        Decoded line, or None when the read timed out.
    """
    raw = ser.readline()
    if not raw:
        return None
    return raw.decode("utf-8", errors="replace").strip()


def _to_int(text):
    """Parse a decimal length field.

    Parameters
    ----------
    text : str
        Candidate decimal text.

    Returns
    -------
    int or None
        Parsed integer, or None on failure.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _split_payload(text, length):
    """Slice the payload field from the +RCV tail fields.

    Parameters
    ----------
    text : str
        Remaining +RCV fields.
    length : int
        Declared payload byte length.

    Returns
    -------
    tuple
        (payload, tail) pair, or (None, None) on malformed data.
    """
    if length >= len(text) or text[length] != ",":
        return None, None
    return text[:length], text[length + 1:]


def _rcv_parts(line):
    """Split a +RCV line into sender, payload text, and declared length.

    Parameters
    ----------
    line : str
        Raw radio line.

    Returns
    -------
    tuple or None
        (sender, text, length) parts, or None on malformed data.
    """
    fields = line[5:].split(",", 2) if line.startswith("+RCV=") else []
    if len(fields) != 3:
        return None
    length = _to_int(fields[1])
    if length is None:
        return None
    return fields[0], fields[2], length


def _parse_rcv(line):
    """Parse one raw +RCV wire line into a record tuple.

    Parameters
    ----------
    line : str
        Raw radio line.

    Returns
    -------
    tuple or None
        (sender, payload, tail) record, or None on malformed data.
    """
    parts = _rcv_parts(line)
    if parts is None:
        return None
    sender, text, length = parts
    payload, tail = _split_payload(text, length)
    if payload is None:
        return None
    return sender, payload, tail


def _le32(value):
    """Encode an integer as four little-endian bytes.

    Parameters
    ----------
    value : int
        Unsigned value to encode.

    Returns
    -------
    bytes
        Four little-endian bytes.
    """
    return value.to_bytes(4, "little")


def _field_key():
    """Return the cached Argon2id field key.

    Parameters
    ----------
    None

    Returns
    -------
    bytes
        Thirty-two byte field key shared with the gate firmware.
    """
    global _FIELD_KEY
    if _FIELD_KEY is None:
        _FIELD_KEY = field_crypto.derive_field_key()
    return _FIELD_KEY


def _record_bytes(seq):
    """Serialize the authorization record a grant would produce.

    Parameters
    ----------
    seq : int
        Sequence number carried by the grant.

    Returns
    -------
    bytes
        Ten-byte serialized authorization record.
    """
    head = bytes([GRANT_FLAG, PENDING_FLAG])
    return head + _le32(seq) + _le32(seq)


def _state_nonce(seq):
    """Build the deterministic state-tag nonce for a sequence number.

    Parameters
    ----------
    seq : int
        Sequence number bound into the nonce.

    Returns
    -------
    bytes
        Twenty-four byte state-tag nonce.
    """
    nonce = bytearray(STATE_NONCE_LEN)
    nonce[0:4] = _le32(seq)
    nonce[4] = STATE_NONCE_DOMAIN
    return bytes(nonce)


def _state_tag(seq):
    """Compute the authenticated state tag for a grant sequence.

    Parameters
    ----------
    seq : int
        Sequence number carried by the grant.

    Returns
    -------
    bytes
        Sixteen-byte tag over the resulting authorization record.
    """
    record = _record_bytes(seq)
    nonce = _state_nonce(seq)
    return field_crypto._xchacha_seal(_field_key(), nonce, record, b"")[1]


def _grant_body(seq):
    """Build the signed body of a sealed desk grant reply.

    Parameters
    ----------
    seq : int
        Sequence number carried by the grant.

    Returns
    -------
    bytes
        Twenty-byte grant body of sequence and state tag.
    """
    return _le32(seq) + _state_tag(seq)


def _seal_grant(seq):
    """Seal a desk grant reply with the field key.

    Parameters
    ----------
    seq : int
        Sequence number carried by the grant.

    Returns
    -------
    str
        Lowercase hex XChaCha20-Poly1305 envelope.
    """
    return field_crypto.seal_field_frame(_grant_body(seq))


def _send_at(ser, address, payload):
    """Submit one AT+SEND command to the transceiver.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    address : str
        Hexadecimal target node address.
    payload : str
        ASCII payload text.

    Returns
    -------
    None
    """
    data = f"AT+SEND={address},{len(payload)},{payload}\r\n"
    ser.write(data.encode("utf-8"))


def _grant(ser, sender, pin):
    """Answer an authenticated request with a sealed grant.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    sender : str
        Authenticated sender address.
    pin : str
        Recovered badge PIN.

    Returns
    -------
    None
    """
    seq = next(_SEQ)
    print(f"GRANT seq={seq} pin={pin}", flush=True)
    _send_at(ser, sender, _seal_grant(seq))


def _write_row(writer, handle, auth, record, pin):
    """Append one request or rejection row to the CSV log.

    Parameters
    ----------
    writer : csv.writer
        Open CSV writer.
    handle : file object
        Flushable log handle.
    auth : str
        Authentication status, either OK or UNAUTHENTICATED.
    record : tuple
        Parsed (sender, envelope, tail) record.
    pin : str
        Recovered PIN, or an empty string when rejected.

    Returns
    -------
    None
    """
    sender, _, tail = record
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    writer.writerow((stamp, sender, auth, pin, tail))
    handle.flush()


def _authenticated(record):
    """Decrypt and authenticate the envelope of one request record.

    Parameters
    ----------
    record : tuple
        Parsed (sender, envelope, tail) record.

    Returns
    -------
    str or None
        Recovered PIN, or None when authentication fails.
    """
    try:
        plaintext = field_crypto.open_field_frame(record[1])
        return plaintext.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _accept(ser, writer, handle, record, pin):
    """Log an authenticated request and answer it with a grant.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    writer : csv.writer
        Open CSV writer.
    handle : file object
        Flushable log handle.
    record : tuple
        Parsed (sender, envelope, tail) record.
    pin : str
        Recovered badge PIN.

    Returns
    -------
    None
    """
    _write_row(writer, handle, "OK", record, pin)
    _grant(ser, record[0], pin)


def _reject(writer, handle, record):
    """Log an unauthenticated request without trusting its forged body.

    Parameters
    ----------
    writer : csv.writer
        Open CSV writer.
    handle : file object
        Flushable log handle.
    record : tuple
        Parsed (sender, envelope, tail) record.

    Returns
    -------
    None
    """
    print(f"UNAUTHENTICATED sender={record[0]}", flush=True)
    _write_row(writer, handle, "UNAUTHENTICATED", record, "")


def _handle_line(ser, writer, handle, line):
    """Process one inbound radio line against the CSV log.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    writer : csv.writer
        Open CSV writer.
    handle : file object
        Flushable log handle.
    line : str
        Raw radio line.

    Returns
    -------
    None
    """
    record = _parse_rcv(line)
    if record is None:
        return
    pin = _authenticated(record)
    if pin is None:
        _reject(writer, handle, record)
        return
    _accept(ser, writer, handle, record, pin)


def _handle_available(ser, writer, handle):
    """Service any radio line that is currently waiting.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    writer : csv.writer
        Open CSV writer.
    handle : file object
        Flushable log handle.

    Returns
    -------
    None
    """
    line = _read_line(ser)
    if line is None:
        return
    print(line, flush=True)
    _handle_line(ser, writer, handle, line)


def main():
    """Run the security desk loop until interrupted.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on clean shutdown.
    """
    args = _parse_args()
    with _open_serial(args.port, args.baud) as ser:
        _provision_radio(ser)
        with open(args.log, "a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if handle.tell() == 0:
                writer.writerow(CSV_HEADER)
            while True:
                try:
                    _handle_available(ser, writer, handle)
                except KeyboardInterrupt:
                    return 0


if __name__ == "__main__":
    sys.exit(main())
