"""Emulator UI target selection must be exact and fail closed."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "locate_live_test_button", ROOT / "scripts/locate_live_test_button.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def xml(*nodes: str) -> str:
    return '<hierarchy rotation="0">' + "".join(nodes) + '</hierarchy>'


def node(text: str, bounds: str, *, clickable="true", enabled="true", kind="android.widget.Button") -> str:
    return (
        f'<node class="{kind}" text="{text}" clickable="{clickable}" '
        f'enabled="{enabled}" bounds="{bounds}" />'
    )


def test_selects_exact_button_center_not_another_action():
    page = xml(
        node("Test APK File", "[0,100][1080,300]"),
        node("Live Test", "[100,520][980,700]"),
        node("Test Installed App", "[0,300][1080,500]"),
    )
    assert MODULE.find_live_test_button(page) == (540, 610)


def test_rejects_wrong_or_disabled_button():
    import pytest
    samples = [
        xml(node("LiveTest", "[100,100][400,300]")),
        xml(node("Live Test", "[100,100][400,300]", clickable="false")),
        xml(node("Live Test", "[100,100][400,300]", enabled="false")),
        xml(node("Live Test", "[100,100][400,300]", kind="android.widget.TextView")),
        xml(node("Live Test", "[0,0][0,0]")),
        xml(node("Live Test", "invalid")),
    ]
    for case in samples:
        with pytest.raises(ValueError):
            MODULE.find_live_test_button(case)


def test_rejects_ambiguous_multiple_live_buttons():
    import pytest
    page = xml(node("Live Test", "[0,100][400,200]"),
               node("Live Test", "[0,300][400,400]"))
    with pytest.raises(ValueError, match="found 2"):
        MODULE.find_live_test_button(page)


def test_malformed_document_rejected():
    from xml.etree import ElementTree
    import pytest
    with pytest.raises(ElementTree.ParseError):
        MODULE.find_live_test_button("<hierarchy><node")
