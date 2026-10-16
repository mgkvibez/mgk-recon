# RESEARCH — mgk-recon
Updated: 2026-10-16

## Market thesis
Agent Skills (installable single-purpose skills for Claude Code / Codex / any
Skills-compatible agent) are the fastest-growing repo category on GitHub right
now. Single-skill repos are pulling 3k+ stars in weeks (geo-sleuth: photo
geolocation, 3k+ stars in <60 days; mono-color-skill: 3.4k). The security-recon
lane in that ecosystem is nearly empty and the existing tools are small or
unfocused.

## Competitive landscape (GitHub, Oct 2026)
| Repo | Stars | Gap we exploit |
|---|---|---|
| Unclecheng-li/DeepSec | 486 | Broad AI security platform, not a focused recon skill |
| zhaji2333/CkSKILLS | 120 | Chinese-language SRC methodology skills, not a standalone recon tool |
| mukul975/Threatswarm | 88 | Full kill-chain swarm (recon->exploit), heavy; we win on focus + safety |
| kvarnelis/deep-recon | 44 | Multi-agent recon + Obsidian; heavy setup |
| frangelbarrera/osint-agent-skills | 36 | OSINT knowledge base, not active domain recon |

## Positioning
"One command, one domain, one dossier." Evidence-based, source-linked, no
false claims. Passive and OSINT-legal techniques only. Dossier output in
Markdown/JSON so agents can consume it.

## Launch playbook
- One-command install (Skills CLI / uvx), zero config
- README: GIF demo above the fold, one-line promise
- Semantic-versioned GitHub releases from day one (v0.1.0 at launch)
- Launch: r/netsec, Show HN, agent-skills awesome lists, X thread with demo
