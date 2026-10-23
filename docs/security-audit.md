# php2shell-scanner — Code Audit

**Audit date:** 2026-10-23
**Audited revision:** branch `ccr-5b37aa9a-amzsk4` (fork of `nathanaelytj/php2shell-scanner`)
**Scope:** `scanner.py` (1,316 lines), `Dockerfile`, `requirements.txt`, `.gitignore`
**Purpose:** Determine whether the tool is safe and valid to run against the operator's own website,
and whether it sends data anywhere other than the target.

---

## 1. Summary verdict

The scanner is a **single self-contained Python script** with only two well-known dependencies
(`h11`, `tqdm`). After a full read of the source:

- **No data leaves your machine except to the target host you specify.** There is no telemetry,
  no analytics, no phone-home, and your results are written only to stdout or a local file.
- **The code is well-engineered and input-hardened** (header-injection safe, bounded response reads,
  TLS on by default, sensitive-header stripping across redirects).
- **It is an *active* probe, not a passive check.** By design it tries to exhaust PHP's memory while
  parsing a crafted multipart body, which can momentarily crash the PHP worker handling that request.
- **Its verdicts need interpretation.** Several verdict paths (notably the empty-500 crash signal and
  the version-string check) produce known false positives / false negatives. Treat a raw `VULNERABLE`
  as "investigate", not "confirmed".

**Bottom line:** safe to run against your own site; trustworthy on *where it sends data*; its *verdicts*
should be corroborated against the server's actual installed PHP build.

---

## 2. Network & data-handling audit (the "does it send things elsewhere" question)

**Only one place in the entire file opens a socket:** `exchange_post` (`scanner.py:494`), via
`loop.create_connection(...)` (`scanner.py:521-531`). The destination is derived **exclusively** from
the URL you pass:

```python
parsed   = urlsplit(target_url)
hostname = parsed.hostname                     # from your URL only
port     = parsed.port or (443 if https else 80)
loop.create_connection(DuplexHTTPProtocol, host=hostname, port=port, ...)
```

Findings:

- **No hardcoded hostnames or URLs** exist in the code. The only domain-like strings are a cosmetic
  `print()` banner (`brought to you by assetnote`, `scanner.py:107`), the `--help` examples
  (`scanner.py:1107-1110`), and the `PHP/x.y.z` version **regex** — none make a network call.
- **No high-level HTTP client** that could hide a callback — it uses raw `asyncio` + `h11`. No
  `requests`, no `urllib.request.urlopen`, no SDK.
- **Results are never transmitted.** Output goes only to the terminal (`print_result`) or to a local
  JSON file via `-o` (`save_results` → `open(output_file, "w")`, `scanner.py:1059`).
- **Only local file I/O:** two `open()` calls — reading your host list / `--path-file`
  (`scanner.py:1012`) and writing your `-o` output (`scanner.py:1059`).
- **No code execution side-channels:** no `subprocess`, `os.system`, `eval`, `exec`, or `__import__`.
- **Redirects are OFF by default.** Only `--follow-redirects` lets it reach any host other than the
  exact URL you gave, and then only wherever *your* site redirects (max 10 hops). On a cross-origin
  redirect it **strips** `Authorization`, `Cookie`, other sensitive headers, and `Host`
  (`scanner.py:631-637`), so credentials do not leak to the redirect target.

**To verify at runtime (zero-trust):** run under a connection monitor (`ss -tnp`, `tcpdump -n`) or an
egress firewall that allows only your target host; the scan will still work, proving nothing else is
contacted.

---

## 3. Impact on the target (important operational caveat)

This is **not a passive scan.** Per tested path it sends:

- one 42-byte multipart **control** request, then
- up to **three probes** of **1 MiB, 8 MiB, and 20 MiB** (`PROBES`, `scanner.py:61`), each a multipart
  body whose field name nests array keys **62 levels deep** (`NESTED_KEYS`, `scanner.py:45`).

That payload is engineered to drive PHP's multipart parser into memory exhaustion — roughly **29 MiB of
upload per path**, and on a susceptible server it can **crash the PHP worker / request** that handles it.
Probing stops as soon as a verdict is reached (`scanner.py:873-926`), and duplicate input URLs are
scanned once (`deduplicate_hosts`, `scanner.py:1023`).

Recommendation: run against **staging first**, or during a low-traffic window, and avoid pointing it at
anything you do not own. The default 60 s timeout (`--timeout`) and `Connection: close` per request keep
each exchange bounded.

---

## 4. Detection-logic validity (how much to trust a verdict)

Verdict core: `check_url` (`scanner.py:795-964`), `crash_signal` (`scanner.py:653-702`),
`version_verdict` + `FIXED_VERSIONS` (`scanner.py:63,642-650`).

### 4.1 Crash signals, in priority order
| Signal | Condition | Fires in SAPI modes | Confidence |
|---|---|---|---|
| **Strong** | probe body contains `Allowed memory size of` + `bytes exhausted` + `Unknown` | all | High — real PHP fatal-error text |
| **Ambiguous** | probe is HTTP 500 with **empty body** while control produced a body | all | Low — see 4.2 |
| FPM worker died | probe status 502/503/504 | auto, fpm | Medium — could be proxy/WAF |
| FPM worker died | probe is HTTP 200 with **empty body** while control produced a body | auto, fpm | Medium |

### 4.2 A crash signal overrides the patched-version check (false-positive path)
Within a probe iteration, `crash_signal` is evaluated and returned on (`scanner.py:917-926`) **before**
the `FIXED` version check (`scanner.py:928`). So a **patched** server that merely OOMs on the 20 MiB
probe and returns an empty 500 is reported **`VULNERABLE`** — and the "this is a patched version" check
is never reached. This matches the upstream-documented false positive (patched PHP 8.4.27 with low
`memory_limit`; PHP 8.3.36 at 128M with a high `max_multipart_body_parts`).
→ **If the reason is "HTTP 500 with an empty body", treat it as unconfirmed.**

### 4.3 Version-based verdict is unreliable on distro packages
`FIXED_VERSIONS = {8.2: 35, 8.3: 36, 8.4: 27, 8.5: 12}` compares only the patch number from
`X-Powered-By`. Debian/RHEL/Ubuntu **backport** the fix while keeping the version string (e.g. a patched
`8.2.7`), which this logic would call **`VULNERABLE`** (7 < 35).
→ **If the reason is "X-Powered-By reports an unpatched release", verify with `php -v` and the distro's
security changelog, not the header.**

### 4.4 Version coverage (blind spot closed)
`FIXED_VERSIONS` lists the four confirmed official fix points (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12,
released 2026-10-21). `version_verdict` (`scanner.py:642-661`) now resolves **every** other branch by
lifecycle position so no advertised version falls through to `NO SIGNAL`:

- Branch **in** the map → exact patch comparison → `FIXED` / `VULNERABLE`.
- Branch **older** than the oldest entry (8.1, 8.0, 7.x, 5.x — the flaw reaches back to PHP 5.4 and these
  received no official release) → **`EOL`**, reported as `VULNERABLE` with an end-of-life reason string.
- Branch **newer** than the newest entry (8.6+, 9.x — ships with the fix upstream) → **`FIXED`**.
- No `PHP/x.y.z` in `X-Powered-By` → `None` → relies on the crash signals (unchanged).

**Remaining caveat (safe direction):** PHP published *source-only* backports for 7.4 / 8.0 / 8.1. A server
that applied one is actually patched but still advertises an EOL version, so it will be reported
`VULNERABLE`. This is the same backport ambiguity as §4.3, erring toward flagging for review — acceptable
because such hosts are unsupported regardless. Confirm with `php -v` + the applied backport.
→ `NO SIGNAL` now occurs only when **no** PHP version is advertised, not for any known branch.

### 4.5 Header dependence
If you hide `X-Powered-By` (common hardening), the version path is inert and detection relies entirely on
the crash signals; a `NO SIGNAL` then means only "could not tell".

### 4.6 Guards that are correct
- A control request that errors or returns ≥500 yields `INCONCLUSIVE` and stops (`scanner.py:827-835`) —
  avoids guessing on a broken endpoint.
- Request-rejection statuses (400/403/411/413/414/417/422/429/431, `scanner.py:62`) are treated as
  "rejected before PHP parsed it", not as crashes.
- phpMyAdmin targets auto-retarget to `/show_config_errors.php` (`scanner.py:837`).

---

## 5. Input / transport hardening (positive findings)

- **Header-injection safe:** `parse_headers` (`scanner.py:114-134`) validates header names against the
  HTTP token charset and rejects CR/LF in values, preventing request-splitting via `-H`.
- **Bounded memory on responses:** response body capped at 1 MiB (`BODY_READ_LIMIT`), headers at 10 MiB
  (`MAX_RESPONSE_HEADER_BYTES`); gzip is decoded incrementally and stored output is capped
  (`decode_gzip_data`, `scanner.py:404-428`).
- **Backpressure:** custom asyncio protocol uses read/write high/low-water marks and pause/resume
  (`scanner.py:236-315`) so large uploads/downloads don't balloon memory.
- **TLS on by default:** default SSL context with ALPN `http/1.1`; `-k/--insecure` disables verification
  explicitly and is announced on stderr (`scanner.py:1226-1227`).
- **IDNA host encoding** and strict percent-encoding of the request target (`scanner.py:331-357`).
- **Docker image is least-privilege:** runs as a non-root `app` user, `--no-create-home`, slim base
  (`Dockerfile`).

---

## 6. Minor issues & robustness notes

- **Exit codes:** `main` exits **1** when a vulnerable host is found, **0** when none, **2** on output
  write failure (`scanner.py:1310-1312`). CI that treats any non-zero exit as a *tool error* will
  misread a successful "found vulnerable" run — branch on the JSON output instead.
- **gzip CPU:** a malicious gzip response is fully *decompressed* (output discarded past 1 MiB) rather
  than aborted early, so a decompression bomb could burn CPU until `--timeout`. Low risk against your own
  site; bounded by the request timeout.
- **`--threads` only matters for host lists;** a single `-u` URL runs its probes sequentially.
- **`requirements.txt` uses `>=` (unpinned).** The Docker base is pinned (`python:3.13-slim`) but Python
  deps float; pin exact versions if you need reproducible/audited runs.

---

## 7. Provenance caveat

This repository is a **fork** (`nathanaelytj/php2shell-scanner`); upstream attribution in the README is
to the Assetnote Security Research Team (discovery credited to the Calif team). Two things this audit
**cannot** establish from the code alone:

1. That the committed code is byte-for-byte the upstream release — **diff this fork against the official
   Assetnote repository** before trusting it in a sensitive environment.
2. That the CVE identifiers (`CVE-2026-109618` / `CVE-2026-109619`) and fixed-version table are accurate —
   **confirm against the CVE records and php.net release notes.**

The audit above covers *behaviour and safety of the code as written*; it is not a verification of the
tool's provenance or of the vulnerability claims.

---

## 8. Recommendations for scanning your own site

1. `pip install -r requirements.txt`, then run with `-v` and capture evidence:
   `python3 scanner.py -u https://yourdomain.example -v -o result.json`
2. Map the verdict:
   - `VULNERABLE` / reason "memory exhausted in Unknown" → strong; still confirm by patching + re-running.
   - `VULNERABLE` / reason "empty body" **or** "X-Powered-By ... unpatched" → *unconfirmed* (§4.2, §4.3).
   - `FIXED` → trustworthy only if `X-Powered-By` is real and not a backport string.
   - `NO SIGNAL` / `INCONCLUSIVE` → not "safe" (§4.4, §4.5); check the installed PHP version directly.
3. The single most reliable check for your own server is non-network: run `php -v` on the box and compare
   against the fixed patch levels (8.2≥35, 8.3≥36, 8.4≥27, 8.5≥12) or confirm your distro backported the
   fix. Use the scanner to *corroborate*, not as the sole source of truth.
4. Prefer staging / low-traffic windows (§3), keep redirects off unless needed, and scan only hosts you
   own.
