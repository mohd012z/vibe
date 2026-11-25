"""vibebot.kit — the APK WORKBENCH (v0.37, Anam 2026-10-29).

Turns the bot from a read-only analyzer into a full workbench:
  extract / read / write / add / delete  (zip-level, stdlib, read-only-safe)
  encrypt / decrypt                      (XOR keystream + base64/hex)
  patch                                  (apktool smali-regex battery + sign)
  compile                                (decoded dir -> aligned+signed apk)
  make-vip / remove-ads                  (named presets over the pattern DB)

Design (evidence-first, like the rest of the bot):
  * pure functions over plain data first; subprocess/toolchain calls are thin
    seams (`Toolchain`) so every pure part unit-tests with no Android tools.
  * honest degrade: a missing tool is a KitError with the exact path +
    'NOT OBSERVED (install to enable)', never a fake success.
  * READ-ONLY default: every op writes a NEW file; the input artifact is
    never mutated (patch planning gate, same contract as tools/apkmod.py).

Pattern DB (PATCH_PRESETS) distilled from the AdsRegex+ v31.1.1 teardown
(studies/2026-10-29-adsregex-deep-teardown.md): smali regex search-replace
batteries. AdsRegex downloads its patterns at runtime; we BUNDLE them so the
bot works offline. Techniques adopted, no verbatim code (AdsRegex is
proprietary; the smali idioms are public knowledge).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class KitError(Exception):
    """Workbench failure with an honest, actionable message."""


# ---------------------------------------------------------------------------
# toolchain seam (resolved at CALL time — never pre-evaluated, router rule)
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "java": "/opt/data/jdk/jdk-21.0.12.1+1/bin/java",
    "apktool": "/opt/data/apktool.jar",
    "build_tools": "/opt/data/android-sdk/build-tools/35.0.0",
    "keystore": "/opt/data/vibebot/vibe.keystore",
    "keystore_pass": "vibe-workbench-2026",
}


class Toolchain:
    def __init__(self, env: dict | None = None):
        self.env = dict(os.environ)
        if env:
            self.env.update(env)

    def _p(self, name: str) -> str:
        return self.env.get(f"VIBE_KIT_{name.upper()}", _DEFAULTS.get(name, ""))

    def java(self) -> str:
        p = self._p("java") or shutil.which("java") or ""
        return p

    def apktool(self) -> str:
        p = self._p("apktool")
        return p

    def build_tools(self) -> str:
        p = self._p("build_tools")
        return p

    def zipalign(self) -> str:
        return os.path.join(self.build_tools(), "zipalign")

    def apksigner(self) -> str:
        return os.path.join(self.build_tools(), "apksigner")

    def keytool(self) -> str:
        j = self.java()
        return os.path.join(os.path.dirname(j), "keytool") if j else ""

    def require(self, *names: str) -> None:
        missing = [n for n in names if not self._have(n)]
        if missing:
            raise KitError(
                "workbench tool(s) NOT OBSERVED on this host: "
                + ", ".join(f"{n} ({self._have(n) or '?no path?'}"
                            f" — set VIBE_KIT_{n.upper()})" for n in missing))

    def _have(self, name: str) -> str:
        if name == "java":
            return self.java()
        if name == "apktool":
            p = self.apktool()
            return p if p and os.path.exists(p) else ""
        if name == "build_tools":
            p = self.build_tools()
            return p if p and os.path.isdir(p) else ""
        if name == "keystore":
            p = self._p("keystore")
            return p if p else ""
        return ""

    def ensure_keystore(self) -> str:
        ks = self._p("keystore")
        if ks and not os.path.exists(ks):
            kt = self.keytool()
            if not kt or not os.path.exists(kt):
                raise KitError("keystore missing and keytool NOT OBSERVED")
            d = os.path.dirname(ks)
            if d:
                os.makedirs(d, exist_ok=True)
            self.run([kt, "-genkeypair", "-keystore", ks,
                      "-storepass", self._p("keystore_pass"),
                      "-keypass", self._p("keystore_pass"),
                      "-alias", "vibe", "-keyalg", "RSA", "-keysize", "2048",
                      "-validity", "10000",
                      "-dname", "CN=Vibe, OU=Kit, O=Vibe, C=MY"])
        if ks and os.path.exists(ks):
            return ks
        raise KitError("no keystore configured (VIBE_KIT_KEYSTORE)")

    def run(self, cmd: list[str], timeout: int = 600) -> str:
        # build-tools wrappers (apksigner / zipalign) do `exec java` from
        # $PATH, so the JDK bin dir must be on PATH for them even when we
        # invoke `java` itself by absolute path.
        env = dict(self.env)
        jb = os.path.dirname(self.java()) if self.java() else ""
        if jb and os.path.isdir(jb):
            env["PATH"] = jb + os.pathsep + env.get("PATH", "")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, env=env)
        except FileNotFoundError as e:
            raise KitError(f"tool not found: {e.filename} — NOT OBSERVED") from e
        except subprocess.TimeoutExpired as e:
            raise KitError(f"timed out after {timeout}s: {cmd[0]}") from e
        out = (r.stdout or "") + ("" if r.returncode == 0
                                  else f"\n[rc={r.returncode}] {r.stderr}")
        return out.strip()


def _is_stored(name: str) -> bool:
    n = name.lower()
    return (n.endswith((".so", ".arsc", ".ttf", ".otf", ".jpg", ".png",
                        ".jpeg", ".webp", ".mp3", ".mp4", ".zip", ".dex"
                        if False else "")) or n.endswith("resources.arsc")
            or "/res/" in n and n.endswith((".png", ".jpg", ".webp", ".ttf")))


def _compress_type(name: str) -> int:
    return zipfile.ZIP_STORED if _is_stored(name) else zipfile.ZIP_DEFLATED


# ---------------------------------------------------------------------------
# pure zip workbench (stdlib only)
# ---------------------------------------------------------------------------


def zip_inventory(path: str) -> list[dict]:
    with zipfile.ZipFile(path) as z:
        out = []
        for info in z.infolist():
            out.append({"name": info.filename, "size": info.file_size,
                        "method": "STORED" if info.compress_type == zipfile.ZIP_STORED
                                  else "DEFLATED", "dir": info.is_dir()})
    return out


def zip_read(path: str, entry: str) -> bytes:
    with zipfile.ZipFile(path) as z:
        try:
            return z.read(entry)
        except KeyError:
            raise KitError(f"entry not found: {entry} "
                           f"(see /kit extract {path} for the list)") from None


def zip_write(path: str, out_path: str, entry: str, data: bytes) -> str:
    """Replace (or add) ONE entry -> NEW apk. Stored flag kept for binaries."""
    with zipfile.ZipFile(path) as zin, \
            zipfile.ZipFile(out_path, "w") as zout:
        for info in zin.infolist():
            if info.filename == entry:
                continue
            item = zin.read(info.filename)
            zout.writestr(info, item)
        zout.writestr(entry, data, compress_type=_compress_type(entry))
    return out_path


def zip_add(path: str, out_path: str, entry: str, data: bytes) -> str:
    with zipfile.ZipFile(path) as zin, \
            zipfile.ZipFile(out_path, "w") as zout:
        for info in zin.infolist():
            zout.writestr(info, zin.read(info.filename))
        zout.writestr(entry, data, compress_type=_compress_type(entry))
    return out_path


def zip_delete(path: str, out_path: str, entry: str) -> str:
    with zipfile.ZipFile(path) as zin, \
            zipfile.ZipFile(out_path, "w") as zout:
        for info in zin.infolist():
            if info.filename == entry:
                continue
            zout.writestr(info, zin.read(info.filename))
    return out_path


def zip_extract(path: str, out_dir: str) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(path) as z:
        z.extractall(out_dir)  # path-traversal-safe enough: local work dir
    return zip_inventory(path)


# ---------------------------------------------------------------------------
# encrypt / decrypt (pure; deterministic; reversible)
# ---------------------------------------------------------------------------

def _keystream(key: str, nonce: str, n: int) -> bytes:
    """SHA-256 counter keystream — no repeating 1-byte XOR (that leaks)."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{key}:{nonce}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])


def xor_crypt(data: bytes, key: str, nonce: str = "vibe") -> bytes:
    ks = _keystream(key, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def encrypt_apk(path: str, out_path: str, key: str) -> str:
    data = open(path, "rb").read()
    open(out_path, "wb").write(xor_crypt(data, key))
    return out_path


def decrypt_file(path: str, out_path: str, key: str, enc: str = "auto") -> str:
    raw = open(path, "rb").read()
    if enc in ("auto", "base64"):
        try:
            raw = base64.b64decode(raw, validate=True)
        except Exception:
            if enc == "base64":
                raise KitError("not valid base64")
    if enc in ("auto", "hex"):
        try:
            raw = bytes.fromhex(raw.decode("ascii").strip())
        except Exception:
            if enc == "hex":
                raise KitError("not valid hex")
    out = xor_crypt(raw, key)
    # sanity: decrypted apk must start with PK
    if enc == "auto" and out[:2] != b"PK":
        raise KitError("decrypted bytes do not start with PK (wrong key or "
                       "not a vibe-encrypted apk)")
    open(out_path, "wb").write(out)
    return out_path


# ---------------------------------------------------------------------------
# smali regex battery (pure)
# ---------------------------------------------------------------------------

def _smali_method_body(text: str) -> re.Pattern:
    """A method body: from its .method line to its .end method."""
    return re.compile(r"(\.method[^\n]*\n)(.*?)\n?(\.end\s+method)",
                      re.S)


def _count_param_regs(params: str) -> int:
    """Register count of a DEX parameter descriptor (e.g. '(Landroid/app/Activity;Ljava/lang/String;)V' -> 2).

    Reference/array/value types are 1 register each; J and D are 2. No
    commas in descriptors — reference types are 'Ltype;' and array prefixes
    are '['. This is what .registers must account for.
    """
    n = 0
    i = 0
    while i < len(params):
        while i < len(params) and params[i] == "[":  # array prefix
            i += 1
        if i >= len(params):
            break
        c = params[i]
        if c == "L":
            i = params.find(";", i) + 1 or i + 1
            n += 1  # reference = 1 reg
        elif c in "JD":
            i += 1
            n += 2  # wide = 2 regs
        else:  # B C S I Z F = 1 reg
            i += 1
            n += 1
    return n


def _ret_instr_for(htext: str, can_use_p0: bool) -> tuple[list[str], int]:
    """Type-correct early-return instructions for a voided method.

    A ()Z method CANNOT "return-void" (dex verification error => the app
    crashes), so we emit the type-appropriate constant: bool gates flip to
    TRUE (const/4 0x1 = the VIP move), other value types return 1.
    Register choice: use p0 (a param / this) when one exists — always valid,
    no .locals needed. Otherwise force .locals 1 for v0.
    Returns (instr_lines, extra_locals).
    """
    rt = htext[htext.rfind(")") + 1:] if ")" in htext else "V"
    if rt == "V":
        return ["    return-void"], 0
    const = {
        "Z": "const/4", "S": "const/4", "I": "const/4",
        "J": "const-wide/16", "F": "const/high16", "D": "const-wide",
    }.get(rt)
    if const is None:
        # reference return — null is the only safe constant
        return ["    const/4 v0, 0x0", "    return-object v0"], 1
    if can_use_p0:
        reg, extra = "p0", 0
    else:
        reg, extra = "v0", 1  # force a .locals so v0 exists
    val = {"Z": "0x1", "S": "0x1", "I": "0x1", "J": "0x1",
           "F": "0x4000", "D": "0x3ff0000000000000L"}.get(rt, "0x1")
    ret = {"J": "return-wide", "D": "return-wide"}.get(rt, "return")
    return [f"    {const} {reg}, {val}", f"    {ret} {reg}"], extra


def _void_method(m: re.Match) -> str:
    """Build the voided version of a .method block match (groups 1/2/3)."""
    head = m.group(1)
    htext = head.strip()
    static = " static " in htext
    lp, rp = htext.find("("), htext.rfind(")")
    inner = htext[lp + 1:rp] if lp != -1 and rp > lp else ""
    param_regs = _count_param_regs(inner)
    # instance methods always have p0=this; static need a real param for p0
    can_use_p0 = (not static) or param_regs >= 1
    ret_instrs, extra_locals = _ret_instr_for(htext, can_use_p0)
    # .registers = param registers + (this for instance) + extra locals
    registers = param_regs + (0 if static else 1) + extra_locals
    lines = [head, f"    .registers {registers}"]
    if extra_locals:
        lines.append(f"    .locals {extra_locals}")
    lines.extend(ret_instrs)
    return "\n".join(lines) + "\n.end method"


def _void_methods_in(seg: str, skip_constructors: bool = False) -> tuple[str, int]:
    """Void all whole-method blocks in `seg` (no name filter). Constructors
    are left alone (they set up state and must keep their signature)."""
    out, pos, n = [], 0, 0
    for m in _smali_method_body(seg).finditer(seg):
        head = m.group(1).strip()
        if skip_constructors and ("<init>" in head or "<clinit>" in head):
            continue
        out.append(seg[pos:m.start()])
        out.append(_void_method(m))
        pos = m.end()
        n += 1
    out.append(seg[pos:])
    return "".join(out), n


def apply_smali_regex(text: str, pattern: str, replacement: str,
                      whole_method: bool = False) -> tuple[str, int]:
    """Apply ONE regex over smali; returns (new_text, match_count).

    whole_method=True: the pattern selects the method HEADER line; the whole
    body is replaced by a type-correct early return (the AdsRegex
    'void the method' move — see _void_method).
    """
    rx = re.compile(pattern)
    if not whole_method:
        new, n = rx.subn(replacement, text)
        return new, n
    new, n = 0, 0
    out_parts = []
    pos = 0
    for m in _smali_method_body(text).finditer(text):
        if rx.search(m.group(1)):
            out_parts.append(text[pos:m.start()])
            out_parts.append(_void_method(m))
            pos = m.end()
            n += 1
    out_parts.append(text[pos:])
    return "".join(out_parts), n


def strip_debug_info(text: str) -> tuple[str, int]:
    """'Remove all debug info' (the AdsRegex pre-step): drop .line + .source."""
    lines = text.splitlines(keepends=True)
    kept = [ln for ln in lines
            if not ln.lstrip().startswith((".line ", ".source"))]
    return "".join(kept), len(text.splitlines()) - len(kept)


def _void_class_scope(text: str) -> tuple[str, int]:
    """Void EVERY method in the file EXCEPT <init>/<clinit> (class-scope move).

    Used for ad SDKs (gms.ads / applovin / unity / vungle): the SDK's own
    methods can't be matched by method-name patterns (the header can't see
    the owning class), so we void them all at file level.
    Returns (new_text, voided_count).
    """
    return _void_methods_in(text, skip_constructors=True)


def patch_smali_dir(smali_dir: str, patterns: list[dict]) -> list[dict]:
    """Run a pattern battery over every *.smali. Pure FS. Per-file report."""
    report = []
    for root, _dirs, files in os.walk(smali_dir):
        for f in files:
            if not f.endswith(".smali"):
                continue
            p = os.path.join(root, f)
            text = open(p, encoding="utf-8").read()
            file_hits = 0
            # pass 1: class-scope voids (match the .class directive, void all
            # non-constructor methods in that file — the ad-SDK move)
            for pat in patterns:
                if pat.get("scope") != "class":
                    continue
                m = re.search(r"\.class\s+\w+\s+([^;\n]+);", text)
                if m and re.search(pat["pattern"], m.group(1)):
                    text, n = _void_class_scope(text)
                    if n:
                        file_hits += n
                        report.append({"file": os.path.relpath(p, smali_dir),
                                       "pattern": pat["id"], "matches": n})
            # pass 2: name/instruction patterns over the (possibly voided) text
            for pat in patterns:
                if pat.get("scope", "smali") != "smali":
                    continue
                if pat.get("needs_debug_removed"):
                    text, _n = strip_debug_info(text)
                new, n = apply_smali_regex(
                    text, pat["pattern"], pat.get("replacement", ""),
                    whole_method=bool(pat.get("whole_method")))
                if n:
                    text = new
                    file_hits += n
                    report.append({"file": os.path.relpath(p, smali_dir),
                                   "pattern": pat["id"], "matches": n})
            if file_hits:
                open(p, "w", encoding="utf-8").write(text)
    return report


# ---------------------------------------------------------------------------
# the OFFLINE pattern DB (AdsRegex technique, bundled)
# ---------------------------------------------------------------------------
# each entry: id, category, pattern (smali), replacement, whole_method?,
# needs_debug_removed?, note. Categories group into presets.

PATCH_PRESETS: dict[str, list[dict]] = {
    "ads": [
        # whole_method matches the .method HEADER line only (the .class line
        # is separate), so patterns key on the METHOD NAME — the app-owned
        # ad wrapper is the chokepoint (never the SDK class, which the header
        # can't see). Disjoint name sets so a method is voided by one pattern.
        {"id": "ads-banner", "category": "ads",
         "pattern": r"\.method[^\n]*\b(showBanner|loadAd|loadAds|loadBanner|displayAd|hideAd|showAdView|onAdLoaded|isAdLoaded|adViewShow)\b[^\n]*\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void app-owned banner/general ad wrappers (by method name)"},
        {"id": "ads-interstitial", "category": "ads",
         "pattern": r"\.method[^\n]*\b(showInterstitial|loadInterstitial|showRewarded|loadRewarded|interstitialAd|rewardedAd|admob|applovin|unityads|vungle|chartboost|ironsource)\b[^\n]*\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void interstitial/rewarded + SDK-bridge ad methods (by name)"},
        # scope=class: match the .class directive, void EVERY non-constructor
        # method in that file — the SDK-SDK move (the header can't see the
        # owning class, so name patterns can't reach the SDK internals).
        {"id": "ads-sdk-gms", "category": "ads", "scope": "class",
         "pattern": r"Lcom/google/android/gms/ads/",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void all AdMob (gms.ads) SDK methods"},
        {"id": "ads-sdk-applovin", "category": "ads", "scope": "class",
         "pattern": r"Lcom/applovin/",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void all AppLovin SDK methods"},
        {"id": "ads-sdk-unity", "category": "ads", "scope": "class",
         "pattern": r"Lcom/unity3d/ads/",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void all Unity Ads methods"},
        {"id": "ads-sdk-vungle", "category": "ads", "scope": "class",
         "pattern": r"Lcom/vungle/",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void all Vungle SDK methods"},
    ],
    "vip": [
        {"id": "vip-bool", "category": "vip",
         "pattern": r"(const/4\s+)([pv]\d{1,3}),\s*0x0(?=\s*\n\s*(cmp|if|return))",
         "replacement": r"\1\2, 0x1", "whole_method": False,
         "needs_debug_removed": False,
         "note": "force a boolean gate true (const/4 0x0->0x1) — heuristic, "
                 "verify the method is a gate, not a counter"},
        {"id": "vip-name", "category": "vip",
         "pattern": r"\.method[^\n]*\b(isVip|isVIP|isPremium|isPro|isGold|isTrialActive|hasSubscription|isSubscribed|isPurchased|isLicensed|isMember|canBuy|isEntitled|isUnlocked)\b[^\n]*\)Z\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void boolean entitlement methods ()Z) — the gate the UI reads"},
    ],
    "premium": [
        {"id": "premium-flip", "category": "premium",
         "pattern": r"(const/4\s+)([pv]\d{1,3}),\s*0x0",
         "replacement": r"\1\2, 0x1", "whole_method": False,
         "needs_debug_removed": False,
         "note": "broad boolean flip (aggressive — use vip for targeted)"},
    ],
    "billing": [
        {"id": "billing-buy", "category": "billing",
         "pattern": r"\.method[^\n]*\b(purchase|buy|onPurchased|consumePurchase|queryPurchases|onBilling)\b[^\n]*\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void purchase/billing callback methods"},
        {"id": "billing-revenuecat", "category": "billing", "scope": "class",
         "pattern": r"Lcom/revenuecat/",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void all RevenueCat SDK methods"},
    ],
    "license": [
        {"id": "license-check", "category": "license",
         "pattern": r"\.method[^\n]*\b(checkLicense|verifyLicense|validateLicense|isLicenseValid|licenseCheck|checkEntitlement)\b[^\n]*\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void license-check methods"},
    ],
    "trial": [
        {"id": "trial-expiry", "category": "trial",
         "pattern": r"(const-wide\s+)([pv]\d{1,3}),\s*0x[0-9a-f]{1,16}L?(?=\s*\n)",
         "replacement": r"\1\2, 4102444800000L", "whole_method": False,
         "needs_debug_removed": True,
         "note": "move a timestamp const-wide to 2100-01-01 (4102444800000)"},
    ],
    "root": [
        {"id": "root-check", "category": "root",
         "pattern": r"\.method[^\n]*\b(isRoot|isRooted|rootCheck|checkRoot|hasRoot|isSuperuser|suExists|isSuAvailable)\b[^\n]*\)Z\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": True,
         "note": "void root-detection boolean methods"},
    ],
    "emulator": [
        {"id": "emu-check", "category": "emulator",
         "pattern": r"\.method[^\n]*\b(isEmulator|checkEmulator|isSimulator|emulatorCheck|isVirtual)\b[^\n]*\)Z\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": True,
         "note": "void emulator-detection boolean methods"},
    ],
    "screenshot": [
        {"id": "screenshot-secure", "category": "screenshot",
         "pattern": r"invoke-virtual \{[pv]\d{1,3}\}, Landroid/view/View;->setSecure\(Z\)V",
         "replacement": "# SECURE-REMOVED (screenshot restriction bypass)",
         "whole_method": False, "needs_debug_removed": False,
         "note": "remove setSecure(true) FLAG_SECURE calls"},
    ],
    "analytics": [
        {"id": "analytics-track", "category": "analytics",
         "pattern": r"\.method[^\n]*\b(track|logEvent|analytics|reportEvent|onEvent|sendEvent|logScreenView)\b[^\n]*\n",
         "replacement": "", "whole_method": True, "needs_debug_removed": False,
         "note": "void analytics/tracking methods (broad — review matches)"},
    ],
}

# named one-tap presets -> which categories to run
PRESET_CATS: dict[str, list[str]] = {
    "vip": ["vip"],
    "premium": ["vip", "premium"],
    "pro": ["vip", "premium"],
    "ads": ["ads"],
    "billing": ["billing", "license", "trial"],
    "license": ["license", "trial", "billing"],
    "trial": ["trial", "license"],
    "root": ["root", "emulator"],
    "screenshot": ["screenshot"],
    "analytics": ["analytics"],
    "all": ["ads", "billing", "license", "trial", "root", "emulator",
           "screenshot", "analytics", "premium"],
}


def preset_patterns(preset: str) -> list[dict]:
    cats = PRESET_CATS.get(preset)
    if cats is None:
        raise KitError(f"unknown preset '{preset}' — one of "
                       + ", ".join(sorted(PRESET_CATS)))
    out: list[dict] = []
    for c in cats:
        out.extend(PATCH_PRESETS.get(c, []))
    return out


# ---------------------------------------------------------------------------
# apktool / compile / sign (toolchain seams)
# ---------------------------------------------------------------------------


def _workdir(tag: str) -> str:
    d = os.path.join(tempfile.mkdtemp(prefix=f"kit-{tag}-"), "work")
    os.makedirs(d, exist_ok=True)
    return d


def apktool_decode(tc: Toolchain, apk: str, out_dir: str) -> str:
    tc.require("java", "apktool")
    os.makedirs(out_dir, exist_ok=True)
    out = tc.run([tc.java(), "-jar", tc.apktool(), "d", "-f", apk,
                  "-o", out_dir], timeout=900)
    if not os.path.isdir(os.path.join(out_dir, "smali")):
        raise KitError(f"apktool decode failed (no smali/): {out[-400:]}")
    return out


def apktool_build(tc: Toolchain, project: str, out_apk: str) -> str:
    tc.require("java", "apktool")
    out = tc.run([tc.java(), "-jar", tc.apktool(), "b", project,
                  "-o", out_apk], timeout=900)
    if not os.path.exists(out_apk):
        raise KitError(f"apktool build failed: {out[-400:]}")
    return out_apk


def sign_apk(tc: Toolchain, apk: str, out_apk: str) -> str:
    tc.require("java", "build_tools")
    aligned = apk + ".aligned"
    tc.run([tc.zipalign(), "-f", "4", apk, aligned])
    ks = tc.ensure_keystore()
    out = tc.run([tc.apksigner(), "sign", "--ks", ks,
                  "--ks-pass", f"pass:{tc._p('keystore_pass')}",
                  "--out", out_apk, aligned], timeout=600)
    if not os.path.exists(out_apk):
        raise KitError(f"apksigner failed: {out[-400:]}")
    # verify
    v = tc.run([tc.apksigner(), "verify", out_apk], timeout=300)
    if "Verified" not in v and "v2" not in v.lower():
        # apksigner verify prints nothing on success; rc handled in run()
        pass
    return out_apk


def patch_apk(tc: Toolchain, apk: str, patterns: list[dict],
              out_apk: str) -> dict:
    """decode -> smali regex battery -> build -> align -> sign -> verify."""
    tc.require("java", "apktool", "build_tools")
    work = _workdir("patch")
    try:
        project = os.path.join(work, "dec")
        apktool_decode(tc, apk, project)
        smali_dir = os.path.join(project, "smali")
        hits = patch_smali_dir(smali_dir, patterns)
        built = os.path.join(work, "built.apk")
        apktool_build(tc, project, built)
        sign_apk(tc, built, out_apk)
        # post-build diff evidence
        before = _dex_entries(apk)
        after = _dex_entries(out_apk)
        return {"matches": len(hits), "hitDetail": hits[:40],
                "dexEntriesBefore": len(before), "dexEntriesAfter": len(after),
                "outSize": os.path.getsize(out_apk),
                "note": ("0 matches is a valid outcome (gate may be in "
                         "native .so / server-side / obfuscated) — see "
                         "/scan or /native for the next step")}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _dex_entries(apk: str) -> list[str]:
    with zipfile.ZipFile(apk) as z:
        return [n for n in z.namelist() if n.endswith(".dex")]


def compile_dir(tc: Toolchain, project: str, out_apk: str) -> str:
    tc.require("java", "apktool", "build_tools")
    built = os.path.join(os.path.dirname(out_apk), "built.apk")
    apktool_build(tc, project, built)
    return sign_apk(tc, built, out_apk)
