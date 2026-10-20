# mgk-recon

> Point your AI agent at a domain. Get back an evidence-based recon dossier.

**Status: v0.1.0 — core dossier shipping.** Tech fingerprinting, redirect chains and header posture work today; DNS/subdomain footprint and dossier diffing shipped in v0.2.0.

mgk-recon is an Agent Skill: installable into Claude Code, Codex or any
Skills-compatible agent (77+ via the Skills CLI). One command, one domain, one
structured dossier:

- Technology fingerprinting (server, framework, CMS, portal signatures)
- HTTP header and security posture analysis
- DNS, subdomain and hosting footprint
- Redirect chain mapping
- Markdown + JSON dossier output, every claim source-linked

Passive and OSINT-legal techniques only. No exploitation, no false claims.

## Quickstart

    python -m mgk_recon example.com --out dossier.md --json dossier.json

18 offline tests (local HTTP fixture, no network):

    python -m unittest discover -s tests

## Install (planned)

    uvx mgk-recon example.com

## Documentation

- [docs/research.md](docs/research.md) — market research and competitive landscape
- [docs/roadmap.md](docs/roadmap.md) — development milestones toward v0.1.0

## License

MIT
