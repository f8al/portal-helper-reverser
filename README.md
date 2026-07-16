# rev.py — static deobfuscator for the `portalhelper` PowerShell family

Recovers obfuscated PowerShell to readable plaintext, extracts the execution
sinks, carves embedded PE payloads, and decrypts the AES-encrypted C2 stage —
**without ever executing the sample**.

---

## Safety contract

This is a **string-recovery interpreter**, not an emulator. It:

- evaluates only the arithmetic and string concatenation the sample uses to
  rebuild its own strings
- **never** runs recovered PowerShell, spawns a shell, or touches the network
  (it will print a C2 URL; it will never contact it)
- withholds payload text from stdout unless you explicitly pass `--show-payload`

The one thing it *does* execute is AES-CBC decryption of a blob **you** supply
locally via `--decrypt-payload`. That's pure math on a local file — no network,
no code execution.

> Outputs are live malware. Decrypted stages and carved DLLs are written with a
> neutral `.bin` extension on purpose. Keep them out of synced, backed-up, or
> AV-scanned paths.

---

## Requirements

- Python 3.8+
- Standard library only for decoding, carving, and reporting
- `--decrypt-payload` additionally needs **one** of:
  ```bash
  pip install cryptography      # or:  pip install pycryptodome
  ```
  If neither is present the tool exits with install instructions (and the
  report still prints an equivalent `openssl` one-liner you can use instead).

---

## Quick start

```bash
python3 rev.py portal-helper.txt                                  # safe triage report + IOCs
python3 rev.py portal-helper.txt --inline --out recovered.ps1     # full deobfuscated script
python3 rev.py portal-helper.txt --dump-pe ./iocs                 # carve embedded PEs
python3 rev.py portal-helper.txt --decrypt-payload foo.mysql \
                                 --decrypt-out payload.bin        # decrypt captured C2 blob
python3 rev.py portal-helper.txt --json                           # machine-readable output
python3 rev.py --self-test                                        # 5 correctness checks
```

---

## How the obfuscation works

Every string is built from arrays of small integers, converted with
`[char](value + KEY)`. The key is never written as a literal — it's bootstrapped
at runtime:

```
"104" and "25"    ->  [int64]"104" + [int64]"25"   = 129
@(-74,-79) + 129  ->  "72"   (a string)
[int64]"72"       =   72     ($NGDJ1L2)
```

Each payload array then decodes as `chr(value + 72)`. `rev.py` reproduces this
math statically and auto-resolves the key (override with `--key N`).

**The part that matters:** the sample decodes ~211 small string *pieces*, then
assembles them into its real scriptblocks with ~160 `$acc += $piece`
concatenations, and dot-sources the result:

```powershell
$piece='';$arr=@(...);for(...){$piece+=[char](...)};$acc+=$piece   # x160
. ([scriptblock]::Create($acc))                                     # the sink
```

Resolving those appends is **data-flow, not execution** — which is why the sinks
can be recovered in full without emulating anything.

---

## Options

| Flag | Purpose |
|---|---|
| `sample` | path to the obfuscated `.txt`/`.ps1` |
| `--key N` | force the additive key (default: auto-resolve, 72) |
| `--out FILE` | write the assembled sinks — the deobfuscated script |
| `--inline` | fold recovered `$variables` into sink bodies (self-contained plaintext) |
| `--show-payload` | print the full decoded payload to stdout (off by default) |
| `--json` | machine-readable summary instead of the text report |
| `--dump-pe DIR` | carve embedded base64 PEs to `DIR/<var>.bin` |
| `--decrypt-payload BLOB` | AES-decrypt a captured C2 blob using scraped key/IV |
| `--decrypt-out FILE` | decrypt destination (default `<BLOB>.decrypted.bin`) |
| `--self-test` | run built-in correctness checks and exit |

### Getting the full deobfuscated script

```bash
python3 rev.py portal-helper.txt --inline --out recovered.ps1
```

All executing code lives in the sinks, so this file *is* the payload. The
`# ===== sink: $name (N chars) =====` separators are valid PowerShell comments.
Omit `--inline` to keep the original `$variable` references.

For literally everything the decoder recovered (all 211 intermediate fragments
plus the assembled sinks):

```bash
python3 rev.py portal-helper.txt --show-payload --inline > everything.txt
```

> `--inline` substitutes **bare** literals — the originals held the string in the
> variable, so quotes aren't reintroduced. The output reads clearly for analysis
> but is not meant to be re-run.

### Carving embedded PEs

`--dump-pe` base64-decodes each candidate, **validates the `MZ` header** (so
base64 that isn't really a PE is rejected), hashes it, and reads the COFF header
for machine and type:

```
$suh7FEOi : PE/MZ x64 dll, 15872 bytes (21164 b64 chars)
    sha256 a29f2c71…57068f
    carved ./iocs/suh7FEOi.bin  (true type .dll; extension left as .bin)
```

The true type is reported but **never** applied to the filename — rename it
yourself when you're ready to load it.

### Decrypting the C2 stage

`extract_crypto()` scrapes the algorithm, mode, padding, key, IV, and C2 URLs
from the assembled sinks, validating as it goes (key must be 16/24/32 bytes, IV
exactly 16) so a bad match is rejected rather than silently producing garbage.
Every run prints them, plus a ready-to-paste `openssl` equivalent:

```
--- payload crypto / C2 (recovered from sinks) ---
  C2 URL    : https://<host>:5173/api/v1/ps1/<id>/payload?gk=<token>
  algorithm : AES-256-CBC / PKCS7 padding
  key (hex) : df36b78f…e516da
  iv  (hex) : 56d47048…fe1a9b
  decrypt   : openssl enc -d -aes-256-cbc -K <key> -iv <iv> -in <blob> -out decrypted.bin
```

Two failure modes are surfaced loudly rather than swallowed, so a bad decrypt
can't masquerade as a good one:

- **PKCS7 padding invalid** → wrong key/IV, or the blob is truncated / isn't this payload
- **blob not 16-byte aligned** → capture is probably incomplete

---

## Identifying an unknown blob

A captured stage has no header and looks like noise. Entropy tells you what it
is before you waste time hunting for a decompressor:

| Signal | Encrypted | Compressed |
|---|---|---|
| Entropy | ~8.0000 bits/byte | high, but **always** has a magic header |
| Magic bytes | none | `1f 8b`, `78 9c`, `28 b5 2f fd`, `PK`, … |
| Length | often block-aligned (`% 16 == 0`) | arbitrary |

Uniform bytes **+ zero magic + block alignment = encrypted, not compressed.**
No amount of `gzip`/`zlib`/`zstd` will parse it; you need the key — and for this
family, the key is in the sinks.

---

## Output formats

**Text report** (default): key, stats, embedded-PE IOCs with hashes, crypto/C2
parameters, and sink inventory. Payload bodies withheld unless `--show-payload`.

**JSON** (`--json`):

```json
{
  "sample": "...", "inlined": false,
  "key":   { "value": 72, "variable": "NGDJ1L2" },
  "stats": { "pieces": 211, "appends": 160, "sinks": 11 },
  "sinks": [ { "variable": "...", "length": 269, "body": "..." } ],
  "embedded_pe":    [ { "variable", "size_bytes", "machine", "pe_type",
                        "md5", "sha1", "sha256", "b64_len", "path" } ],
  "payload_crypto": { "algorithm", "mode", "padding",
                      "key_b64", "iv_b64", "key_hex", "iv_hex",
                      "key_bits", "urls" },
  "decrypted_payload": null
}
```

Raw PE bytes are never serialised into JSON — hashes and metadata only.
`decrypted_payload` populates when combined with `--decrypt-payload`.

Example — extract IOCs for a pipeline:

```bash
python3 rev.py portal-helper.txt --json | jq -r '.embedded_pe[].sha256'
python3 rev.py portal-helper.txt --json | jq -r '.payload_crypto.urls[]'
```

---

## Self-tests

```bash
python3 rev.py --self-test
```

1. Key `72` decodes a known header fragment
2. Accumulator assembly, sink capture, and variable inlining
3. Embedded-PE detection, hashing, and COFF type parsing (synthetic PE32+)
4. AES key/IV/mode/URL scraped from sink text
5. AES-CBC decrypt round-trip — encrypt a known plaintext, decrypt through the
   tool's own path, assert padding validates and bytes match

Tests 3–5 build synthetic inputs and use self-cleaning temp dirs — no live
sample required.

---

## Worked example: `portal-helper.ps1`

| | |
|---|---|
| Additive key | `72` (auto-resolved from `$NGDJ1L2`) |
| String pieces | 211 |
| `+=` appends | 160 |
| Execution sinks | 11 |
| Embedded PEs | 2 × x64 DLL (15,872 B / 3,000 B) |
| C2 stage | AES-256-CBC → 24 MB x64 GUI EXE, 10 sections |

Recovered behaviour chain:

1. `$env:__SP` capture (the one genuine `iex` — 38 chars, sets an env var only)
2. **AMSI bypass** — reflect `AmsiUtils`, set `amsiInitFailed = $true`
3. **ScriptBlock-logging + ETW bypass** — clear `signatures`, null `PSEtwLogProvider`
4. **Console hiding** — dynamic P/Invoke `ShowWindow`
5. **Persistence** — copy self to `xdg-desktop-portal` / `wireplumber` /
   `gstreamer` / `babl` paths, `Hidden,System` attributes
6. **Mutex** — single-instance guard, `exit` if already running
7. **COM hijack** — `HKCU\Software\Classes\CLSID\…\InProcServer32` → dropped DLL
8. **Download** — `Net.WebClient` with cert validation disabled
9. **AES-256-CBC decrypt** — key/IV embedded in the sinks
10. **Reflective load** — `VirtualAlloc` / `VirtualProtect` the decrypted PE

---

## Extending to a new sample

Most variants only change the statement *shapes*. The regexes to adjust:

| Regex | Matches |
|---|---|
| `CHAR_LOOP` | `$out='';$arr=@(...);for(...){$out+=[char](...)}` |
| `STR_APPEND` / `STR_ASSIGN` | `$acc+=$src` / `$acc=$src` |
| `INT_ASSIGN` / `EMPTY_INIT` | key bootstrap math, `$v=''` |
| `SINK` | `iex`, `Invoke-Expression`, `[scriptblock]::Create`, `&` |
| `AES_KEY_RE` / `AES_IV_RE` / `URL_RE` | payload crypto and C2 |

If the key bootstrap changes, `--key N` bypasses auto-resolution entirely.

**Known limitation:** if a sample's first `iex` genuinely *defines* the
downstream sink variables (true self-modification), that requires emulation and
is out of scope by design. This family doesn't — its sinks are plain
concatenation, which is why static recovery gets 100% of them.
