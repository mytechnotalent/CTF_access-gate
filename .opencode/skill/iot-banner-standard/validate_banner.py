#!/usr/bin/env python3
"""Validate a repository banner against the IoT banner standard.

Checks that <repo>.png exists at the repository root, is a 2400x2400 PNG of a
reasonable size, that banner.json carries every required key, and that the
README references the banner with the exact raw GitHub URL. Run from the
repository root; exit zero means the banner conforms.
"""
import json
import sys
from pathlib import Path

from PIL import Image

SIZE = (2400, 2400)
MIN_BYTES = 100_000
REQUIRED = ("repo", "eyebrow", "title", "subtitle", "accent", "bg", "icon",
            "panel_status", "chips", "terminal", "categories", "cards",
            "footer")
ICONS = ("thermo", "leaf", "drop")


def _repo_name() -> str:
    """
    Return the repository name from the working directory.

    Parameters
    ----------
    None

    Returns
    -------
    str
        The repository directory name.
    """
    return Path.cwd().name


def _image_line(repo: str) -> str:
    """
    Build the expected banner image line.

    Parameters
    ----------
    repo : str
        The repository name.

    Returns
    -------
    str
        The expected Markdown image line.
    """
    url = f"https://raw.githubusercontent.com/mytechnotalent/{repo}/main"
    return f"![{repo}]({url}/{repo}.png)"


def _png_errors(path: Path) -> list[str]:
    """
    Check the banner PNG dimensions and size.

    Parameters
    ----------
    path : pathlib.Path
        The banner PNG path.

    Returns
    -------
    list[str]
        PNG diagnostics.
    """
    if not path.is_file():
        return [f"{path}: missing banner PNG"]
    errors = []
    if Image.open(path).size != SIZE:
        errors.append(f"{path}: expected {SIZE}, got {Image.open(path).size}")
    if path.stat().st_size < MIN_BYTES:
        errors.append(f"{path}: PNG smaller than {MIN_BYTES} bytes")
    return errors


def _spec_errors(path: Path, repo: str) -> list[str]:
    """
    Check banner.json keys and values.

    Parameters
    ----------
    path : pathlib.Path
        The banner.json path.
    repo : str
        The repository name.

    Returns
    -------
    list[str]
        Spec diagnostics.
    """
    if not path.is_file():
        return ["banner.json: missing"]
    spec = json.loads(path.read_text(encoding="utf-8"))
    errors = [f"banner.json: missing key {key}"
              for key in REQUIRED if key not in spec]
    if spec.get("repo") != repo:
        errors.append("banner.json: repo does not match the directory")
    if spec.get("icon") not in ICONS:
        errors.append("banner.json: icon must be thermo, leaf, or drop")
    return errors


def _readme_errors(repo: str) -> list[str]:
    """
    Check the README references the banner on its first line.

    Parameters
    ----------
    repo : str
        The repository name.

    Returns
    -------
    list[str]
        README diagnostics.
    """
    path = Path("README.md")
    if not path.is_file():
        return ["README.md: missing"]
    first = path.read_text(encoding="utf-8").splitlines()[0]
    if first != _image_line(repo):
        return [f"README.md line 1: expected {_image_line(repo)!r}"]
    return []


def main() -> int:
    """
    Validate the repository banner.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero when the banner conforms, otherwise one.
    """
    repo = sys.argv[1] if len(sys.argv) > 1 else _repo_name()
    errors = _png_errors(Path(f"{repo}.png"))
    errors += _spec_errors(Path("banner.json"), repo)
    errors += _readme_errors(repo)
    print("\n".join(errors))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
