#!/usr/bin/env python3
"""Сборка пакетов DeviateProxy для Firefox и Chromium (Chrome, Edge, Opera)."""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
COMMON = SRC / "common"
DIST = ROOT / "dist"
UNPACKED = DIST / "unpacked"
TARGETS = ("firefox", "chrome")
SKIP_NAMES = {".DS_Store", "Thumbs.db"}


TARGET_EXCLUDE = {
    "firefox": {"generate-pac.js"},
    "chrome": set(),
}


def copy_tree_filtered(src: Path, dst: Path, exclude_names: set[str] | None = None) -> None:
    excludes = SKIP_NAMES if exclude_names is None else (SKIP_NAMES | exclude_names)
    for item in src.rglob("*"):
        if item.is_file() and item.name not in excludes:
            rel = item.relative_to(src)
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def prepare_unpacked(target: str) -> Path:
    out_dir = UNPACKED / target
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    # 1. Shared common assets and scripts
    copy_tree_filtered(COMMON, out_dir, TARGET_EXCLUDE.get(target))

    # 2. Browser-specific files (manifest, background, etc.)
    target_src = SRC / target
    if not target_src.is_dir():
        raise SystemExit(f"Папка {target_src} не найдена")
    copy_tree_filtered(target_src, out_dir)

    # 3. License
    license_file = ROOT / "LICENSE"
    if license_file.is_file():
        shutil.copy2(license_file, out_dir / "LICENSE")

    manifest = out_dir / "manifest.json"
    if not manifest.is_file():
        raise SystemExit(f"Ошибка: manifest.json отсутствует в {out_dir}")

    return out_dir


def create_zip(source_dir: Path, zip_dest: Path) -> int:
    zip_dest.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(zip_dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(source_dir.rglob("*")):
            if p.is_file() and p.name not in SKIP_NAMES:
                zf.write(p, p.relative_to(source_dir).as_posix())
                count += 1
    with zipfile.ZipFile(zip_dest) as zf:
        if "manifest.json" not in zf.namelist():
            raise SystemExit(f"{zip_dest.name}: manifest.json должен быть в корне архива")
    return count


def main() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)

    manifest_fx = json.loads((SRC / "firefox" / "manifest.json").read_text(encoding="utf-8"))
    version = manifest_fx["version"]

    print(f"=== Сборка DeviateProxy v{version} ===")

    for target in TARGETS:
        unpacked_dir = prepare_unpacked(target)
        zip_path = DIST / f"deviateproxy-{target}-{version}.zip"
        file_count = create_zip(unpacked_dir, zip_path)
        size_kb = zip_path.stat().st_size / 1024
        print(f"[{target.capitalize()}]")
        print(f"  Unpacked: {unpacked_dir}")
        print(f"  Archive:  {zip_path.name} ({file_count} файлов, {size_kb:.1f} KB)")

        if target == "firefox":
            xpi_path = DIST / f"deviateproxy-firefox-{version}.xpi"
            shutil.copy2(zip_path, xpi_path)
            print(f"  Firefox:  {xpi_path.name} (.xpi пакет)")

    print(f"\nВсе пакеты успешно собраны в: {DIST}")


if __name__ == "__main__":
    main()
