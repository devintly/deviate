#!/usr/bin/env python3
"""Собрать zip/xpi-пакет Firefox-расширения Deviate."""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SKIP_NAMES = {".DS_Store", "Thumbs.db"}
FILES = (
    "manifest.json",
    "background.js",
    "popup.html",
    "popup.js",
    "list.html",
    "list.js",
    "pac-parse.js",
    "icon.png",
    "icon-off.png",
    "LICENSE",
)


def pack_firefox(dest: Path) -> int:
    missing = [name for name in FILES if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit("Нет файлов: " + ", ".join(missing))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in FILES:
            path = ROOT / name
            if path.name in SKIP_NAMES:
                continue
            zf.write(path, name)
    with zipfile.ZipFile(dest) as zf:
        if "manifest.json" not in zf.namelist():
            raise SystemExit(f"{dest.name}: manifest.json должен быть в корне архива")
    return len(FILES)


def main() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    version = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))["version"]
    zip_path = DIST / f"deviate-firefox-{version}.zip"
    count = pack_firefox(zip_path)
    print("Сборка пакета Deviate (Firefox):")
    print(f"  {zip_path.name}: {count} файлов, {zip_path.stat().st_size} байт")
    xpi_path = DIST / f"deviate-firefox-{version}.xpi"
    shutil.copyfile(zip_path, xpi_path)
    print(f"  {xpi_path.name}: копия zip для Firefox")
    print(f"Готово: {DIST}")


if __name__ == "__main__":
    main()
