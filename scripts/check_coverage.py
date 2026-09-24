#!/usr/bin/env python3
"""Run native unit tests and verify 100% C source code coverage."""
import os
import subprocess
import sys
from pathlib import Path
from run_tests import (
    _find_compiler,
    _include_flags,
    _owned_sources,
    _sources,
)


def _compile_coverage_bin(out_bin: Path) -> int:
    """
    Compile test binary with LLVM coverage instrumentation.

    Parameters
    ----------
    out_bin : pathlib.Path
        Output test binary path.

    Returns
    -------
    int
        Compiler return code.
    """
    flags = ["-fprofile-instr-generate", "-fcoverage-mapping", "-O0", "-g"]
    flags += ["-Wall", "-Wextra", "-fcommon", "-o", str(out_bin)]
    cmd = [_find_compiler()] + flags + _include_flags() + _sources()
    return subprocess.run(cmd).returncode


def _execute_prof(out_bin: Path, profraw: Path) -> int:
    """
    Execute instrumented test binary emitting profraw data.

    Parameters
    ----------
    out_bin : pathlib.Path
        Test executable path.
    profraw : pathlib.Path
        Raw profile output path.

    Returns
    -------
    int
        Process return code.
    """
    env = dict(os.environ, LLVM_PROFILE_FILE=str(profraw))
    return subprocess.run([str(out_bin)], env=env).returncode


def _merge_profile(profraw: Path, profdata: Path) -> int:
    """
    Merge raw profile into indexed profdata.

    Parameters
    ----------
    profraw : pathlib.Path
        Raw profile path.
    profdata : pathlib.Path
        Indexed profile output path.

    Returns
    -------
    int
        llvm-profdata return code.
    """
    cmd = ["xcrun", "llvm-profdata", "merge", "-sparse", str(profraw)]
    cmd += ["-o", str(profdata)]
    return subprocess.run(cmd).returncode


def _report_coverage(out_bin: Path, profdata: Path) -> str:
    """
    Generate coverage text report for owned C files.

    Parameters
    ----------
    out_bin : pathlib.Path
        Instrumented test binary.
    profdata : pathlib.Path
        Indexed profdata path.

    Returns
    -------
    str
        Summary coverage report output.
    """
    cmd = ["xcrun", "llvm-cov", "report", str(out_bin)]
    cmd += [f"-instr-profile={profdata}"] + _owned_sources()
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout


def _verify_full_coverage(report: str) -> bool:
    """
    Verify report demonstrates 100% line coverage on all owned files.

    Parameters
    ----------
    report : str
        Coverage table text.

    Returns
    -------
    bool
        True when all files have 100.00% line coverage.
    """
    names = ("crc.c", "sensor.c", "display.c", "radio.c", "status_led.c",
             "button.c", "servo.c", "ir_remote.c", "keypad.c", "auth.c",
             "chacha20.c", "poly1305.c", "crypto_aead.c", "blake2b.c",
             "argon2.c", "crypto_kdf.c", "envelope.c", "monitor.c")
    print(report)
    for line in report.splitlines():
        fields = line.split()
        if fields and any(fields[0] == name for name in names):
            if fields[9] != "100.00%":
                return False
    return True


def _generate_profile(out_dir: Path) -> Path | None:
    """
    Build, execute instrumented tests, and merge profile data.

    Parameters
    ----------
    out_dir : pathlib.Path
        Output directory for profile artifacts.

    Returns
    -------
    pathlib.Path or None
        Merged profile data path, or None on failure.
    """
    out_bin = out_dir / "test_cov"
    profraw = out_dir / "test_cov.profraw"
    profdata = out_dir / "test_cov.profdata"
    if _compile_coverage_bin(out_bin) != 0:
        return None
    if _execute_prof(out_bin, profraw) != 0:
        return None
    if _merge_profile(profraw, profdata) != 0:
        return None
    return profdata


def main() -> int:
    """
    Execute coverage pipeline and verify 100% coverage.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on 100% coverage success, otherwise non-zero.
    """
    out_dir = Path("build/test")
    out_dir.mkdir(parents=True, exist_ok=True)
    profdata = _generate_profile(out_dir)
    if profdata is None:
        return 1
    report = _report_coverage(out_dir / "test_cov", profdata)
    return 0 if _verify_full_coverage(report) else 1


if __name__ == "__main__":
    sys.exit(main())