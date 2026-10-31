#!/usr/bin/env python3
"""Find the *visible* Live Test button in an Android uiautomator XML dump."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from xml.etree import ElementTree

BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def find_live_test_button(xml: str) -> tuple[int, int]:
    root = ElementTree.fromstring(xml)
    candidates: list[tuple[int, int]] = []
    for node in root.iter("node"):
        if node.attrib.get("text", "").strip() != "Live Test":
            continue
        if node.attrib.get("class") != "android.widget.Button":
            continue
        if node.attrib.get("enabled", "true") != "true":
            continue
        if node.attrib.get("clickable", "false") != "true":
            continue
        if node.attrib.get("bounds") is None:
            continue
        match = BOUNDS.fullmatch(node.attrib["bounds"])
        if not match:
            continue
        x1, y1, x2, y2 = map(int, match.groups())
        if x2 <= x1 or y2 <= y1:
            continue
        candidates.append(((x1 + x2) // 2, (y1 + y2) // 2))
    if len(candidates) != 1:
        raise ValueError(
            "expected exactly one enabled clickable Live Test button; "
            f"found {len(candidates)}"
        )
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml_dump", type=Path)
    args = parser.parse_args()
    try:
        x, y = find_live_test_button(args.xml_dump.read_text(encoding="utf-8"))
    except (OSError, ValueError, ElementTree.ParseError) as error:
        print(f"Cannot locate Live Test button: {error}", file=sys.stderr)
        return 2
    print(f"{x} {y}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
