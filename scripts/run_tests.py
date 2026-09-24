#!/usr/bin/env python3
"""Compile and execute the native unit test suite."""
import shutil
import subprocess
import sys
from pathlib import Path


def _find_compiler() -> str:
    """
    Locate host C compiler.

    Parameters
    ----------
    None

    Returns
    -------
    str
        Path or command name for host C compiler.
    """
    return shutil.which("clang") or shutil.which("gcc") or "cc"


def _owned_sources() -> list[str]:
    """
    Return owned module C source files.

    Parameters
    ----------
    None

    Returns
    -------
    list[str]
        Firmware module source path strings.
    """
    return [
        "src/crc.c",
        "src/sensor.c",
        "src/display.c",
        "src/radio.c",
        "src/status_led.c",
        "src/button.c",
        "src/servo.c",
        "src/ir_remote.c",
        "src/keypad.c",
        "src/auth.c",
        "src/chacha20.c",
        "src/poly1305.c",
        "src/crypto_aead.c",
        "src/blake2b.c",
        "src/argon2.c",
        "src/crypto_kdf.c",
        "src/envelope.c",
        "src/monitor.c",
    ]


def _sources() -> list[str]:
    """
    Compose the full native test translation unit list.

    Parameters
    ----------
    None

    Returns
    -------
    list[str]
        Harness and adapter test source paths.
    """
    return [
        "test/harness/harness.c",
        "test/test_access_gate_and_security.c",
        "test/test_peripheral_and_crypto.c",
    ]


def _include_flags() -> list[str]:
    """
    Compose compiler include flags.

    Parameters
    ----------
    None

    Returns
    -------
    list[str]
        Include flags for compilation.
    """
    return [
        "-Iinclude",
        "-Itest",
        "-Itest/mock",
        "-Itest/harness",
    ]


def _compile_test_binary(out_bin: Path) -> int:
    """
    Compile test binary with host C compiler.

    Parameters
    ----------
    out_bin : pathlib.Path
        Output executable destination path.

    Returns
    -------
    int
        Compiler return code.
    """
    flags = ["-Wall", "-Wextra", "-O2", "-fcommon", "-o", str(out_bin)]
    cmd = [_find_compiler()] + flags + _include_flags() + _sources()
    return subprocess.run(cmd).returncode


def _execute_test(out_bin: Path) -> int:
    """
    Execute compiled test binary.

    Parameters
    ----------
    out_bin : pathlib.Path
        Test executable path.

    Returns
    -------
    int
        Test process exit code.
    """
    return subprocess.run([str(out_bin)]).returncode


def main() -> int:
    """
    Build and execute test suite.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Process return code.
    """
    out_dir = Path("build/test")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_bin = out_dir / "test_access_gate_and_security"
    rc = _compile_test_binary(out_bin)
    return _execute_test(out_bin) if rc == 0 else rc


if __name__ == "__main__":
    sys.exit(main())