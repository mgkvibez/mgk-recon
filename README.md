# mgk-recon

> Point your AI agent at a domain. Get back an evidence-based recon dossier.

**Status: early development.** This repo is public research + planning until the first release.

mgk-recon is an Agent Skill: installable into Claude Code, Codex or any
Skills-compatible agent (77+ via the Skills CLI). One command, one domain, one
structured dossier:

- Technology fingerprinting (server, framework, CMS, portal signatures)
- HTTP header and security posture analysis
- DNS, subdomain and hosting footprint
- Redirect chain mapping
- Markdown + JSON dossier output, every claim source-linked

Passive and OSINT-legal techniques only. No exploitation, no false claims.

## Install (planned)

    uvx mgk-recon example.com

## Documentation

- [docs/research.md](docs/research.md) — market research and competitive landscape
- [docs/roadmap.md](docs/roadmap.md) — development milestones toward v0.1.0

## License

MIT
