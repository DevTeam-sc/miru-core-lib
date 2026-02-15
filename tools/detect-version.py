import os
from pathlib import Path
import re
import sys
from typing import Iterator


SOURCE_ROOT = Path(__file__).resolve().parent.parent

_SEMVERISH_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].+)?$")


def detect_version() -> str:
    override = os.environ.get("MIRU_VERSION")
    if override is not None:
        override = override.strip()
        if override == "":
            raise SystemExit("MIRU_VERSION is set but empty")
        if _SEMVERISH_VERSION_PATTERN.match(override) is None:
            raise SystemExit(
                f"MIRU_VERSION must look like X.Y.Z (optionally with -suffix/+meta); got {override!r}"
            )
        return override

    releng_location = next(enumerate_releng_locations(), None)
    if releng_location is not None:
        sys.path.insert(0, str(releng_location.parent))
        from releng.miru_version import detect
        version = detect(SOURCE_ROOT).name
        if version == "0.0.0":
            version = "16.5.7"
    else:
        version = "16.5.7"
    return version


def enumerate_releng_locations() -> Iterator[Path]:
    val = os.environ.get("MIRU_RELENG")
    if val is not None:
        custom_releng = Path(val)
        if releng_location_exists(custom_releng):
            yield custom_releng

    val = os.environ.get("MESON_SOURCE_ROOT")
    if val is not None:
        parent_releng = Path(val) / "releng"
        if releng_location_exists(parent_releng):
            yield parent_releng

    local_releng = SOURCE_ROOT / "releng"
    if releng_location_exists(local_releng):
        yield local_releng


def releng_location_exists(location: Path) -> bool:
    return (location / "miru_version.py").exists()


if __name__ == "__main__":
    print(detect_version())
