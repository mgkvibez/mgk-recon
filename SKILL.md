---
name: mgk-recon
description: Point the agent at a domain and produce an evidence-based recon dossier — technology fingerprinting, redirect chain mapping and security header posture, every claim source-linked, passive and OSINT-legal techniques only. Use when the user asks to profile, fingerprint or run recon on a website or domain.
---

# mgk-recon

One command, one domain, one structured dossier. Passive only —
no exploitation, no false claims, every claim carries its source.

## Requirements

- Python 3.10+ (standard library only)
- Network access to the target over HTTPS/HTTP

## Commands

Profile a domain (markdown dossier to stdout):

```console
python -m mgk_recon example.com
```

Save markdown + JSON dossiers:

```console
python -m mgk_recon example.com --out dossier.md --json dossier.json
```

Tests (offline, local HTTP fixture):

```console
python -m unittest discover -s tests
```

## What the dossier contains

- **Redirect chain** — every hop with its status code
- **Technologies** — server and x-powered-by headers, body markers
  (frameworks, CMS generators), and safe path probes; each match
  cites the exact header, marker or probe that produced it
- **Security header posture** — HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy; present and missing are
  both reported as sourced claims, plus a 0–1 posture score

## Interpreting results

- An "evidence" line is the contract: if a claim has no source, it is
  a bug — report it as one.
- A fetch error is recorded, not hidden; the dossier still renders
  with status 0 and the error text.
- Missing security headers are observations, not verdicts: the client
  may mitigate elsewhere (e.g. CSP enforced at a proxy).

## Scope rules (hard limits)

- Passive/OSINT-legal only: fetching public pages and reading headers.
- No exploitation, no intrusive scanning, no auth bypass attempts.
- Path probes are limited to two well-known, read-only URLs.
