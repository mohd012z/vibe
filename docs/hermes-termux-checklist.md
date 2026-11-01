# Hermes Inspector — phone-first RM0 verification (not yet device-tested)

This is a **local Termux development workflow**, not an installable APK.
The inspector only accepts APKs you own or have permission to inspect.
It binds to 127.0.0.1 and does not expose a public network service.

## Termux installation commands

Install Termux from a maintained official distribution, then enter:

```sh
pkg update
pkg install -y python git curl
git clone --branch feature/read-only-hermes-inspector-20261101 --single-branch \
  https://github.com/mohd012z/vibe.git
cd vibe
python -m unittest discover -s tests -p 'test_vibe_hermes*.py' -v
python tools/vibe_hermes_mobile.py --port 8765
```

Open **http://127.0.0.1:8765** in a browser on the same phone and choose a locally stored, authorized APK. Use the browser's file chooser; there is no document-folder import permission or background service.

## Optional Hermes disassembler

Read-only inventory and HBC version detection use Python's standard library only.
The **Search Hermes strings/functions** button also requires the upstream
`hbctool` command, independently installed in Termux. Its official
HBC100 release is available at
https://github.com/Kirlif/HBC-Tool/releases/tag/100

```sh
curl -fL -o hbctool-0.1.7-py3-none-any.whl \
  https://github.com/Kirlif/HBC-Tool/releases/download/100/hbctool-0.1.7-py3-none-any.whl
python -m pip install ./hbctool-0.1.7-py3-none-any.whl
hbctool --version
```

The wheel's installation and disassembly have **not been verified on Android**.
The optional source repairs tested in CI are **not** installed into the
published upstream wheel. Use the pinned audited source in a separate working
copy for experiments, never modify originals or claim a patched wheel.

## Security and resource boundaries

- Localhost only; browser token, origin and Host checks, no network APIs.
- 96 MiB mobile upload limit; single active analysis, 20-second upload read timeout.
- 48 MiB bytecode extraction cap; 16 MiB output cap; 30-second disassembler subprocess timeout.
- Temporary files deleted when requests complete; original APK remains read-only.
- Max 2,000 indexed strings and functions; 10,000 explicit string references.
- The interface renders untrusted bytes using textContent, not HTML markup.
- HBC96–100 bundles reporting nonempty BigInt sections are refused by the optional disassembler path because the upstream parser does not explicitly consume those sections.

## Acceptance gates not yet executed

Termux install/permissions, browser lifecycle, rotation and responsive layouts
on a physical Android device, low-memory behavior, long-lived local listener
lifecycle, and real-device performance. Run these on a phone before describing
the feature as Android-ready. No billable services are required by these commands.
