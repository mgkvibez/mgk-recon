# Changelog

## v0.3.0 — 2026-10-27

- **Cert-transparency monitoring**: --ct-baseline records the
  crt.sh certificate set for the target; --ct-diff compares the
  current set against that baseline and reports every new
  certificate (issuer, not-before, names) as a change event.
  One-shot footprint becomes a monitoring primitive.
- **Passive checks** (--passive): security.txt presence, DMARC/SPF
  TXT presence and a TLS certificate summary (CN, issuer, validity
  window), all strictly read-only, all reported as source-linked
  evidence. Advisory wording: 'no issues found by ruleset v0.3.0'.
- Suite grown to 32 tests (6 CT, 8 passive).

## v0.2.0 — 2026-10-20

- DNS/subdomain hosting footprint: CT-log enumeration (crt.sh),
  stdlib resolution, live/dead counts and shared-host clustering
- Dossier comparison: --diff against a previous JSON dossier reports
  technology changes, posture regressions and redirect moves
- CLI: --footprint and --diff flags
- 7 new tests (18 total)


## v0.1.0 — 2026-10-20

- Core dossier: technology fingerprinting (headers, body markers, safe
  path probes), redirect chain mapping with status codes, security
  header posture (HSTS, CSP, XFO, XCTO, Referrer-Policy) with a 0-1 score.
- Markdown + JSON output; every claim carries its evidence source.
- Agent skill manifest (`SKILL.md`) with hard scope rules.
- 11 offline tests against a local HTTP fixture.
