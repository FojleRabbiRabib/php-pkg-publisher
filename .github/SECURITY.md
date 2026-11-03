# Security Policy

Once the publisher ships, this service will sign repository metadata that users install
software from, so a vulnerability here could reach every user of the repository.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). Reports are triaged as they arrive; you will
get a response with an assessment and, once confirmed, a fix timeline.

## Scope (applies as each component ships)

- Anything that makes the publisher admit, sign or serve a package that failed
  verification (cosign identity, checksums, package signature).
- The webhook receiver accepting a forged, replayed or oversized request, or
  gaining any privilege beyond touching its nudge file.
- Code or command injection from release, webhook or configuration data.
- Disclosure of key material, tokens or secrets.
- Today, the repository tooling: a CI pin lint that accepts a floating dependency.

## What is out of scope

- Vulnerabilities in GitHub, Cloudflare, `apt`, `dnf`, `cosign` or other tools
  that reproduce without this project; report those upstream.
