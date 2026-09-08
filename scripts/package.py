#!/usr/bin/env python3
"""Собрать zip/xpi-пакеты расширения MeguProxy."""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SKIP_NAMES = {".DS_Store", "Thumbs.db"}

TARGETS = (
    ("Chrome", "meguproxy-chrome", False),
    ("FireFox", "meguproxy-firefox", True),
    ("EdgeOpera", "meguproxy-edge", False),
)


def pack_dir(src: Path, dest: Path) -> int:
    files = [
        path
        for path in sorted(src.rglob("*"))
        if path.is_file() and path.name not in SKIP_NAMES
    ]
    if not any(path.name == "manifest.json" for path in files):
        raise SystemExit(f"В {src} нет manifest.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, path.relative_to(src).as_posix())
    with zipfile.ZipFile(dest) as zf:
        names = zf.namelist()
        if "manifest.json" not in names:
            raise SystemExit(f"{dest.name}: manifest.json должен быть в корне архива")
    return len(files)


def main() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    print("Сборка пакетов MeguProxy:")
    for folder, name, make_xpi in TARGETS:
        src = ROOT / folder
        if not src.is_dir():
            raise SystemExit(f"Нет каталога {src}")
        version = json.loads((src / "manifest.json").read_text(encoding="utf-8"))["version"]
        zip_path = DIST / f"{name}-{version}.zip"
        count = pack_dir(src, zip_path)
        size = zip_path.stat().st_size
        print(f"  {zip_path.name}: {count} файлов, {size} байт")
        if make_xpi:
            xpi_path = DIST / f"{name}-{version}.xpi"
            shutil.copyfile(zip_path, xpi_path)
            print(f"  {xpi_path.name}: копия zip для Firefox")

    print(f"Готово: {DIST}")


if __name__ == "__main__":
    main()
