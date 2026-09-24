"""Unit test adapter for VS Code Test Explorer."""
import subprocess
import sys
import unittest

_CACHED_OUTPUT = ""


def _get_harness_output() -> str:
    """
    Execute native tests and return stdout.

    Parameters
    ----------
    None

    Returns
    -------
    str
        Standard output from native test suite.
    """
    global _CACHED_OUTPUT
    if not _CACHED_OUTPUT:
        cmd = [sys.executable, "scripts/run_tests.py"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        _CACHED_OUTPUT = res.stdout
    return _CACHED_OUTPUT


def _assert_harness_pass(test_name: str) -> None:
    """
    Assert that a named harness test passed.

    Parameters
    ----------
    test_name : str
        Name of harness test function.

    Returns
    -------
    None
    """
    output = _get_harness_output()
    expected = f":{test_name}:PASS"
    assert expected in output, f"{test_name} did not pass in harness output"


class TestAccessGateFirmware(unittest.TestCase):
    """Test cases for RP2350 Access Gate firmware."""

    def test_00_harness_clean(self) -> None:
        """
        Verify the native harness reports no failures.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        assert "0 failures" in _get_harness_output()

    def test_01_config_constants(self) -> None:
        """
        Verify provisioning constants.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_config_constants")

    def test_02_keypad_accumulate(self) -> None:
        """
        Verify the keypad PIN accumulator.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_keypad_accumulate")

    def test_03_auth_apply_window(self) -> None:
        """
        Verify the authorization anti-replay window.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_auth_apply_window")

    def test_04_monitor_grant_success(self) -> None:
        """
        Verify a valid desk grant opens the deadbolt.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_grant_success")

    def test_05_monitor_grant_replay(self) -> None:
        """
        Verify a captured grant cannot be replayed.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_grant_replay")

    def test_06_monitor_state_tag_tamper(self) -> None:
        """
        Verify a debugger flip of the verdict is rejected.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_state_tag_tamper")

    def test_07_monitor_rex_unlock(self) -> None:
        """
        Verify the request-to-exit egress path opens the deadbolt.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_monitor_rex_unlock")

    def test_08_status_led_show(self) -> None:
        """
        Verify the annunciator show states.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_status_led_show")

    def test_09_envelope_known_vector(self) -> None:
        """
        Verify the committed envelope known-answer vector.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        _assert_harness_pass("test_envelope_known_vector")


if __name__ == "__main__":
    unittest.main()
