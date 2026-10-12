# Shieldwall

One-screen Linux security dashboard. Firewall, open ports, SSH logins, pending updates, secret scans. An armor-style health meter. Read-only in MVP. Built on OpenShield and SentryClaw.

## Problem

Linux security status is scattered across `nft`, `ss`, `journalctl`, the package manager, and a secrets grep. A mercenary desk needs one glance: is the wall intact, or is a plate missing.

OpenShield is the terminal agent. SentryClaw is the self-hosted reviewer. Neither is a host-health screen. Shieldwall is that screen, using their stack and rule style instead of a new agent.

## Target users

- A developer on a single Linux workstation or a small VPS who already runs OpenShield.
- Someone who wants a local, non-cloud view of exposure. No account, no telemetry.

Not a SOC, not an EDR product, not a managed scanner for other people's machines.

## Features

### MVP

- One screen. No navigation. Five plates and one meter.
- Firewall plate: detect nftables, firewalld, or ufw; show enabled/disabled and default policy. Read-only.
- Open ports plate: listening TCP/UDP from `ss` (or `/proc`), process name when permitted, flag unexpected listeners.
- SSH plate: recent accepted and failed logins from the journal or auth log, last N events, source address.
- Updates plate: pending updates via apt, dnf, or pacman check commands. No install.
- Secrets plate: run the existing scanner against a chosen repo path. Show hit path and rule id, not the secret value.
- Armor meter: five plates, each intact / scored / broken. Overall as a shield fill (steel intact, bone worn, blood if a plate is broken).
- Local only. Binds to 127.0.0.1 if it serves a page, or runs as a TUI. No cloud upload.
- Explain (optional): send a *redacted* finding summary to a local OpenShield or compatible local endpoint. Never send secret material or raw auth logs off-box by default.

### Later

- Multi-host agent that only pushes plate summaries.
- SentryClaw-style YAML rules for "this port is allowed."
- Scheduled snapshot diff. Still no auto-remediation in the default install.
- Polar-paid watch pack: saved baselines and a weekly local report. Not required for the one screen.

## Architecture & stack

Rust binary, same generation as OpenShield (`/workspace/openshield`, Rust 1.91+) and SentryClaw (`/workspace/sentryclaw`). TUI first, using the Blackshield palette already shipped in OpenShield. Optional single HTML page on localhost, following SentryClaw's local dashboard idea, not its GitHub webhook server.

Collectors are separate processes or functions with a timeout. They emit a plate struct: status, evidence lines, error. The meter is a pure function of plate statuses. Missing permission is "unknown," not "healthy."

```
collectors (read-only, unprivileged where possible)
  nft/firewalld/ufw | ss | journal | apt/dnf/pacman | secrets-scanner
        |
        v
plate model --> armor meter --> one screen (TUI or 127.0.0.1)
        |
        +-- optional redacted explain --> local OpenShield / local endpoint
```

Privilege: the MVP runs as the user. Firewall and auth-log reads may fail; the plate says so. Do not ship a setuid helper in MVP. A later polkit helper can be read-only.

Secret scans call `/workspace/shop/secrets-scanner` as a subprocess if present, else a thin reimplementation of its file walk with the same "do not print the secret" rule. Do not shell out to an unbounded agent.

Rule severity can follow SentryClaw's YAML/TOML rule shape (`/workspace/sentryclaw/README.md`: custom rules with severity). A port allowlist is data, not code.

## UI wireframes

```
+------------------------------------------------------------------+
| SHIELDWALL                                          host: local  |
|                                                                  |
|        [##########::::]  ARMOR 72    steel / one plate open      |
|                                                                  |
|  FIREWALL     PORTS        SSH          UPDATES      SECRETS    |
|  nft enabled  4 listen     1 fail/24h   12 pending   0 hits      |
|  drop in      :22 ssh      last: lan    apt          ./repo      |
|  [intact]     :443 ?       [scored]     [scored]     [intact]    |
|               [broken]                                            |
+------------------------------------------------------------------+
| :443  caddy   not in allowlist          [copy evidence]          |
| no changes will be applied from this screen                      |
+------------------------------------------------------------------+
```

## Monetization fit

Free core, Apache-2.0, matching `/workspace/openshield` (LICENSE Apache-2.0).

The one screen, collectors, and meter are free. A later Polar-paid pack can add baseline files, multi-host rollup, and a PDF report generated locally. Do not paywall the read of the user's own firewall.

Open core only if the paid pack is a separate binary. The free binary must be useful alone.

## Reuse of existing repos

- `/workspace/openshield` — Rust codebase, install pattern (`install.sh`, `~/.local/bin`), Blackshield TUI palette, local compatible client for optional explain. Do not require the agent to start the dashboard.
- `/workspace/openshield/README.md` — provider config lives in `~/.config/openshield/config.toml`. Shieldwall should read that only if the user turns explain on.
- `/workspace/sentryclaw` — Rust service layout, TOML config, severity rules, Prometheus-style metrics if a later exporter is added, local web dashboard pattern. Do not take a dependency on GitHub App auth.
- `/workspace/sentryclaw/config.example.toml` — config style reference (host, port, sections). Shieldwall default port is localhost-only.
- `/workspace/shop/secrets-scanner` — secret scan plate. Shop listing describes a scanner; call it, do not fork blindly. Confirm its CLI before wiring.
- `/workspace/shop/blackshield-terminal` and `/workspace/shop/blackshield-plasma` — existing Blackshield visual packs in the shop tree. Use as palette reference only after reading them; do not assume APIs.

## Risks

- A green shield is not a pentest. Label the meter as plate coverage, not "secure."
- Auto-remediation (closing ports, enabling firewalls, installing updates) can lock out SSH. MVP is read-only. Later writes need a typed confirmation and a rollback note.
- Auth logs and secret hits are sensitive. Default explain path must strip addresses, usernames, and match text, or stay off.
- Running collectors via an OpenShield agent that can execute arbitrary tools turns a dashboard into a remote shell. Collectors are fixed commands.
- Privilege creep: a root helper that accepts strings from the UI is an injection hole. No shell concatenation of UI input.
- False secrets (test keys, placeholders) will train users to ignore the plate. Show rule id and path; allow a local ignore file.
- Package-manager check commands differ by distro and can block on locks. Timeout and show "unknown."

## MVP estimate

3–4 weeks for one developer: five collectors, plate model, TUI, armor meter, secrets-scanner subprocess, localhost-only. Explain-via-OpenShield is a fifth week and easy to cut.
