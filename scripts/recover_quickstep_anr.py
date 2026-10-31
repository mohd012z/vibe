#!/usr/bin/env python3
"""Detect only the known Android Quickstep ANR overlay in uiautomator XML."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.etree import ElementTree

BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def recovery_coordinates(xml: str) -> tuple[int, int] | None:
    root = ElementTree.fromstring(xml)
    nodes = list(root.iter("node"))
    titles = [n for n in nodes if n.get("resource-id") == "android:id/alertTitle"
              and n.get("text") == "Quickstep isn't responding" and n.get("package") == "android"]
    if len(titles) != 1:
        return None
    waits = [n for n in nodes if n.get("resource-id") == "android:id/aerr_wait"
             and n.get("text") == "Wait" and n.get("class") == "android.widget.Button"
             and n.get("package") == "android" and n.get("enabled") == "true"
             and n.get("clickable") == "true"]
    if len(waits) != 1:
        raise ValueError("Quickstep ANR has no unique safe Wait action")
    m = BOUNDS.fullmatch(waits[0].get("bounds", ""))
    if not m:
        raise ValueError("Quickstep Wait bounds missing")
    x1, y1, x2, y2 = map(int, m.groups())
    if x1 >= x2 or y1 >= y2:
        raise ValueError("Quickstep Wait bounds invalid")
    return ((x1 + x2) // 2, (y1 + y2) // 2)


if __name__ == "__main__":
    try:
        coords = recovery_coordinates(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if coords is None:
            sys.exit(1)
        print(*coords)
    except (IndexError, OSError, ValueError, ElementTree.ParseError) as exc:
        print(f"Quickstep recovery unavailable: {exc}", file=sys.stderr)
        sys.exit(2)
