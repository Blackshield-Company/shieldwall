![shieldwall](.github/preview.png)

# Shieldwall

One-screen read-only Linux security dashboard. Five plates — firewall, open ports, SSH logins, pending updates, secret hits — and an armor meter.

This MVP is Python 3 (stdlib only), not the Rust binary sketched in DESIGN.md. It runs as the invoking user. It does not install packages, change firewall rules, or use a setuid helper.

Author: synthalorian  
Contact: blackshield@mail.grokbot.com  
License: Apache-2.0

The meter is **plate coverage, not a security guarantee**.

## Build

No third-party packages. From this directory:

```
python3 -m shieldwall --help
```

Optional install, so the `shieldwall` console script is on `PATH`:

```
python3 -m pip install --no-deps .
```

## Run

```
python3 -m shieldwall
python3 -m shieldwall --no-color
python3 -m shieldwall --json
python3 -m shieldwall serve
python3 -m shieldwall --config config.example.toml serve --host 127.0.0.1 --port 8787
```

`serve` binds to loopback only and refuses any other host. It serves one HTML page plus `GET /api/plates`. Nothing on that screen changes the machine.

Copy `config.example.toml` to `~/.config/shieldwall/config.toml`. Until `[ports] allow` lists the listeners you expect, every listening port is unexpected and the ports plate is broken.

Colors use the Blackshield palette: blood `#8b0000`, steel `#8c9ca8`, bone `#e8dcc4`, void `#0c0c0e`. `--no-color` or `NO_COLOR` turns ANSI off.

Plate status is `intact`, `scored`, `broken`, or `unknown`. A missing tool or a permission error is `unknown`, never `intact`. The meter scores intact 20, scored 10, broken 0, unknown 0 (max 100). Label is `steel` only when every plate is intact, `blood` if any plate is broken, otherwise `bone`.

Collectors are fixed argument lists with a timeout. They do not invoke a shell. Secret output is path and rule id only.

## Test

```
python3 -m unittest discover -s tests -v
```

## Known gaps

- No explain feature. Redacted findings are not sent to a local endpoint.
- Text screen and localhost HTML, not a full terminal UI.
- No multi-host agent, snapshot diff, baseline pack, or local report export.
- No remediation. Closing ports, enabling a firewall, or installing updates is out of scope.
- No polkit or setuid helper. Unreadable firewall state or logs stay `unknown`.
- Port allowlist is TOML, not a YAML rule pack. An empty allowlist flags every listener.
- If more than one firewall tool is installed, the first readable policy wins: nftables, then firewalld, then ufw.
- SSH covers the last N matching events in the journal tail (or auth log), not a strict 24 hour query. Usernames are omitted; source addresses are shown.
- The built-in secret scanner is a small rule set and can false-positive. `secretsweep scan <path> --format json` is used when that command is on `PATH`. `.shieldwallignore` is local only.
- Package-manager checks differ by distro and report `unknown` on lock, timeout, or a missing tool. They never install.

## Web checklist

`web/` is a static, browser-only version: paste firewall, `ss`, SSH log, pending-update and config/compose output and get the same five plates plus a fix-it checklist. The rules are a JavaScript port of the Python collectors (`web/src/rules.js`), with a parity test that runs the same inputs through both. Nothing leaves the browser: there is no backend, and the page's Content-Security-Policy sets `connect-src 'none'`. Fonts are bundled.

```
cd web
npm test        # node --test, no dependencies
npm run build   # static site in web/dist
```

Open `/#sample` to load a sample setup.
