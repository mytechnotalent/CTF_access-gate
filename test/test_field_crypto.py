"""Unit tests for the OPERATION COLD IRON field cryptography module."""
import importlib.util
import unittest
from pathlib import Path

_MODULE = Path(__file__).resolve().parent.parent / "scripts/field_crypto.py"
_SPEC = importlib.util.spec_from_file_location("field_crypto", _MODULE)
field_crypto = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(field_crypto)

RFC_TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
FIELD_KEY = "65cf0755162dbcd45bb4cdb93602cb9f5f8b774d8393833d6fa63093261fb339"
FRAME_CT = "ac04242c7e6d9246bdb6546168d6ba3535298f969e9307b3c2efc58c3be1"
FRAME_TAG = "4e4137a7551a358aaf990e40cbf47234"
PLAINTEXT = b'{"n":7,"s":12,"t":235,"h":610}'


class TestFieldCrypto(unittest.TestCase):
    """Test cases for Argon2id and XChaCha20-Poly1305 field frames."""

    def test_rfc9106_argon2id_vector(self) -> None:
        """Verify the RFC 9106 Argon2id known-answer vector.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        tag = field_crypto._argon2id(
            bytes([1]) * 32, bytes([2]) * 16, 3, 32, 4, 32, 2,
            bytes([3]) * 8, bytes([4]) * 12)
        self.assertEqual(tag.hex(), RFC_TAG)

    def test_field_key_matches_firmware(self) -> None:
        """Verify the field profile key matches the firmware vector.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        self.assertEqual(field_crypto.derive_field_key().hex(), FIELD_KEY)

    def test_envelope_matches_firmware(self) -> None:
        """Verify a sealed frame matches the firmware byte layout.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        nonce = bytes(range(24))
        ciphertext, tag = field_crypto._xchacha_seal(
            field_crypto.derive_field_key(), nonce, bytes([7]), PLAINTEXT)
        self.assertEqual(ciphertext.hex(), FRAME_CT)
        self.assertEqual(tag.hex(), FRAME_TAG)

    def test_seal_open_round_trip(self) -> None:
        """Verify a sealed frame opens back to the plaintext.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        envelope = field_crypto.seal_field_frame(PLAINTEXT)
        self.assertEqual(field_crypto.open_field_frame(envelope), PLAINTEXT)

    def test_flipped_tag_rejected(self) -> None:
        """Verify a flipped authentication tag is rejected.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        raw = bytearray(bytes.fromhex(field_crypto.seal_field_frame(
            PLAINTEXT)))
        raw[-1] ^= 0x01
        with self.assertRaises(ValueError):
            field_crypto.open_field_frame(bytes(raw).hex())

    def test_flipped_ciphertext_rejected(self) -> None:
        """Verify flipped ciphertext is rejected.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        raw = bytearray(bytes.fromhex(field_crypto.seal_field_frame(
            PLAINTEXT)))
        raw[24] ^= 0x01
        with self.assertRaises(ValueError):
            field_crypto.open_field_frame(bytes(raw).hex())

    def test_malformed_frame_rejected(self) -> None:
        """Verify malformed hexadecimal frames are rejected.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        for candidate in ("", "00", "zz"):
            with self.assertRaises(ValueError):
                field_crypto.open_field_frame(candidate)


if __name__ == "__main__":
    unittest.main()
