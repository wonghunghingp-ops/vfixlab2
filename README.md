# Node2Shell — CVE-2026-111497: Node.js Brotli Decoder Out-of-Bounds Write RCE (FixLab Verified)

[中文版](README_CN.md) | [FixLab 官网](https://vfixlab.com)

## Overview

Node2Shell is a critical remote code execution (RCE) vulnerability in the Brotli decoder bundled with Node.js, tracked as CVE-2026-111497 (CVSS 9.2). A malformed Brotli stream declares a single block type and then illegally switches blocks; the vulnerable decoder misreads the format error as "needs more input" and keeps appending writes past an 8-byte internal buffer, corrupting decoder state. When an application uses `node:zlib` to decompress attacker-controlled Brotli data, that corruption can be driven to arbitrary command execution as the Node process user — in our lab, as `uid=1000(node)`.

**FixLab verified this end to end in an isolated lab**: RCE on Node 24.22.0, and a clean block on the patched Node 24.22.1. If you run an affected Node line, upgrade to the fixed release for your line (22.23.4, 24.22.1, or 26.12.1). That is the fix.

## Quick facts

| Item | Value |
|---|---|
| Vulnerability | Node2Shell — Brotli decoder out-of-bounds write → RCE |
| CVE | CVE-2026-111497 |
| CVSS | 9.2 (critical) |
| Affected Node.js | 22.x < 22.23.4, 24.x < 24.22.1, 26.x < 26.12.1 |
| EOL lines | 20.x and other end-of-life lines have no fix — upgrade to a supported line |
| Brotli versions listed as affected in the source | 1.0.3–1.0.9, 1.1.0, 1.2.0 |
| Trigger precondition | The application must use `node:zlib` to decompress attacker-controlled Brotli data |
| Upstream fix | Brotli adds `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17): an illegal block switch is a format error; fixed Node returns `ERR__ERROR_FORMAT_BLOCK_SWITCH` and the service survives |
| Confirmed vulnerable (FixLab lab) | Node 24.22.0 (Express 5.3.0 app, loopback only) |
| Fixed version (verified) | Node 24.22.1 |
| FixLab verification | RCE verified on 24.22.0; blocked on 24.22.1 (see below) |

## Affected and fixed versions

- **Vulnerable:** Node.js 22.x before 22.23.4, 24.x before 24.22.1, 26.x before 26.12.1.
- **Fixed:** 22.23.4, 24.22.1, 26.12.1 (use the fixed release for your line).
- **End-of-life lines (for example 20.x):** no fix is provided — upgrade to a supported line.
- Version alone is not the whole story: the flaw is only reachable if an application decompresses attacker-controlled Brotli data. Running a vulnerable Node version with no such path does not by itself expose an endpoint — but any app that does decompress untrusted Brotli input on a pre-fix Node is exposed.

## How it works

At a high level, the chain is:

1. The application decompresses attacker-controlled Brotli data with `node:zlib`. In our lab this is an Express app accepting `Content-Encoding: br` request bodies; the same class of trigger applies to `fetch()` responses from a malicious server and to direct `zlib` calls on untrusted input.
2. The malformed Brotli stream declares a single block type, then illegally switches blocks.
3. The vulnerable decoder misreads the format error as "needs more input" and keeps writing past an 8-byte internal buffer, corrupting decoder state.
4. The corruption is driven into a return-oriented-programming chain that redirects execution to an attacker command, whose output returns over the exploited connection.

Two practical notes that matter for reproduction and defense:

- **Reproduction is probabilistic.** The lab RCE depends on ASLR layout guessing (the dominant layout appears in only a fraction of fresh processes) plus strict lab conditions: the official Node 24.22.0 x86-64 non-PIE binary (pinned by digest in the lab Dockerfile), Express 5.3.0 with body-parser 2.4.0, `UV_THREADPOOL_SIZE=1`, a supervisor that restarts the worker, and the accepted socket file descriptor. Our first round went 16/16 failed before the second round passed. Failure to reproduce on a first attempt does **not** mean a target is safe.
- **This is a runtime flaw, not an application bug.** Any application that hands attacker-controlled Brotli data to `node:zlib` on a vulnerable Node build is exposed through that path. Filtering at the application layer is not a substitute for the Node upgrade.

## FixLab verification

All work was done in isolated Docker containers on our own range server, bound to loopback only (`127.0.0.1`). No third-party system was touched. No real credentials were involved.

### Vulnerable: Node 24.22.0 — RCE verified

- **Target:** Express 5.3.0 (body-parser 2.4.0) with `express.json()`, `POST /upload` (JSON, default 100kb body limit), `GET /health` returning `PONG`, on `127.0.0.1:3000`, under a supervisor loop that restarts Node, with `UV_THREADPOOL_SIZE=1`, running the official Node 24.22.0 x86-64 non-PIE binary pinned by digest in the lab Dockerfile.
- **Tool:** the public proof-of-concept by dimasma0305, profile `node-24.22.0-express-5.3.0-bookworm-x86_64` (standard library only, run with host Python 3.10), up to 16 fresh supervised processes per round.
- **Attack surface:** `POST /upload` with a Brotli body under `Content-Encoding: br`; body-parser decompresses via `node:zlib` → out-of-bounds write → ROP chain (`dup2` onto the accepted socket fd 19 → `execvp`) → the `id` command's output returns over the exploited HTTP connection.
- **Result (round 1: 16/16 failed; round 2, attempt 3: PASS):**
  - Round 1: all 16 attempts failed (staged position stable at `0x137ed748`, each round resetting on the network crash trigger, last response empty).
  - Round 2, attempt 3: `PASS: RCE verified by fresh id output through the declared interface` — proof channel = HTTP request socket stdout, proof command = `id`, proof stdout = `uid=1000(node) gid=1000(node) groups=1000(node)`.
- **Conclusion:** CVE-2026-111497 gives end-to-end RCE against this Express-on-Node-24.22.0 setup (Brotli OOB write → ROP → arbitrary command as the Node user).

### Fixed: Node 24.22.1 — blocked

- **Target:** the same lab, with only the Dockerfile base changed to `node:24.22.1-bookworm` (Express and body-parser configuration untouched, so the comparison is isolated to the Node version); the version was confirmed as `v24.22.1` via a one-shot container; on `127.0.0.1:3000`.
- **Result:** the same proof-of-concept returned FAIL — `network crash trigger did not stop the current Express worker` (the malicious input no longer crashes the worker, so the exploit chain cannot start; the proof-of-concept stopped after the first attempt). After the proof-of-concept run, the service was alive: `/health` returned `PONG` and a normal `/upload` returned `DONE`.
- **Conclusion:** Node 24.22.1 blocks this exploit and keeps serving. Upgrade to the fixed release for your line.

### Honest boundary — what we did not claim

- The first round's 16/16 failures are probabilistic ASLR-guessing variance (the same pattern as the PHP lab on a 2-core host), not evidence of safety. The second round passed, and that is the result that counts.
- We verified the Express network-RCE profile only. Other profiles in the same proof-of-concept repository (stock Node denial-of-service profiles and worker/fetch/next/undici/axios labs) were not run here; do not read this writeup as covering them.
- Early secondary coverage described the repository as denial-of-service only; we follow the repository's current README (updated 2026-10-23) and its profiles data, which mark this Express profile as RCE-verified.
- No turnkey weaponized exploit is published in this repository. The mechanism is described so defenders can detect and fix it; the verification used a public proof-of-concept in an isolated lab.

## Detection — how to check if you are affected

1. **Version check (fastest):** run `node --version`. If the version is 22.x before 22.23.4, 24.x before 24.22.1, or 26.x before 26.12.1, treat the host as vulnerable and upgrade.
2. **Reachability check:** does any application path decompress attacker-controlled Brotli data? Check for `Content-Encoding: br` request handling, `fetch()` of untrusted responses, and direct `zlib` calls on untrusted input. If such a path exists on a pre-fix Node, treat the flaw as reachable.
3. **Compromise indicators (if a vulnerable build was exposed):** repeated Node worker crashes or restarts in a short window, unexplained processes running as the Node user, and unexpected outbound connections from Node workers. If any indicator is present, treat the host as potentially compromised and rebuild from a clean image — do not just upgrade and assume cleanliness.
4. Do **not** run untrusted proof-of-concept code against production systems to "test" this. Version-check, then patch.

## Fix and remediation

1. **Upgrade Node to the fixed release for your line: 22.23.4, 24.22.1, or 26.12.1 (or later).** This is the fix.
2. Rebuild container images from patched bases — do not just patch a running container and keep its layers.
3. If the host ran a vulnerable build while exposed, hunt for compromise (see Detection above) before declaring it clean. Rebuild from scratch if the hunt is inconclusive.
4. As defense in depth, audit where attacker-controlled Brotli data enters the application (br-encoded request bodies, fetched responses) — but the Node upgrade is the fix, and input filtering alone is not a substitute for it.

## References

- CVE-2026-111497 — Node.js Brotli decoder out-of-bounds write → RCE (CVSS 9.2).
- Node.js security advisory (affected lines 22.x / 24.x / 26.x and fixed releases 22.23.4 / 24.22.1 / 26.12.1).
- Brotli decoder error `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17); Node's `ERR__ERROR_FORMAT_BLOCK_SWITCH` on fixed builds.
- Public proof-of-concept used in our lab (isolated, loopback only): https://github.com/dimasma0305/CVE-2026-111497-POC

## About FixLab

FixLab (飞克实验室) is a vulnerability research and remediation service: every vulnerability we report is reproduced in our own isolated lab, and every fix is run through end to end before we publish it. If a fix cannot be verified, we say so instead of claiming it.

- Website: https://vfixlab.com
- Related FixLab verified writeups: [PHP2Shell (CVE-2026-109618 / CVE-2026-109619)](https://github.com/wonghunghingp-ops/vfixlab1) · [LiteLLM 1.107.0 supply-chain compromise](https://github.com/wonghunghingp-ops/vfixlab3) · [Cursor trojanized extension](https://github.com/wonghunghingp-ops/vfixlab4) · [GitLab Onigmo (CVE-2026-97229)](https://github.com/wonghunghingp-ops/vfixlab5)

Content here may be shared with attribution to FixLab and a link to https://vfixlab.com.
