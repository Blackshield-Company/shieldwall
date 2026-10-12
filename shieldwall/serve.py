import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from shieldwall.model import DISCLAIMER
from shieldwall.palette import HEX

class LoopbackRefusal(ValueError):
    pass


def is_loopback_host(host: str) -> bool:
    if host is None:
        return False
    text = host.strip().strip("[]")
    if not text:
        return False
    if text.lower() == "localhost":
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return bool(address.is_loopback)


def ensure_loopback(host: str) -> str:
    if not is_loopback_host(host):
        shown = host if host is not None else ""
        raise LoopbackRefusal(f"refusing non-loopback host: {shown}")
    return host.strip().strip("[]")


def bind_host(host: str) -> str:
    text = ensure_loopback(host)
    if text.lower() == "localhost":
        return "127.0.0.1"
    return text


def format_url(host: str, port: int) -> str:
    if ":" in host:
        return f"http://[{host}]:{port}/"
    return f"http://{host}:{port}/"


def _esc(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(report: dict) -> str:
    meter = report.get("meter") or {}
    label = str(meter.get("label") or "bone")
    if label not in ("steel", "bone", "blood"):
        label = "bone"
    score = int(meter.get("score") or 0)
    host = _esc(report.get("host") or "local")
    plates = report.get("plates") or []
    cards = []
    evidence_lines = []
    for plate in plates:
        status = str(plate.get("status") or "unknown")
        cards.append(
            "<article class='plate'>"
            f"<h2>{_esc(str(plate.get('name') or '').upper())}</h2>"
            f"<p>{_esc(plate.get('headline') or '')}</p>"
            f"<p>{_esc(plate.get('detail') or '')}</p>"
            f"<p class='tag { _esc(status) }'>[{_esc(status)}]</p>"
            "</article>"
        )
        if status == "broken":
            for line in (plate.get("evidence") or [])[:2]:
                evidence_lines.append(_esc(line))
    if not evidence_lines:
        for plate in plates:
            if plate.get("error"):
                evidence_lines.append(_esc(f"{plate.get('name')}: {plate.get('error')}"))
    evidence = "".join(f"<li>{line}</li>" for line in evidence_lines[:4])
    fill = HEX.get(label, HEX["bone"])
    css = f"""
body {{ margin: 0; background: {HEX['void']}; color: {HEX['bone']};
  font: 14px/1.45 ui-monospace, monospace; }}
main {{ max-width: 920px; margin: 0 auto; padding: 24px; }}
header {{ display: flex; justify-content: space-between; align-items: baseline; }}
h1 {{ color: {HEX['blood']}; letter-spacing: 0.12em; font-size: 20px; margin: 0; }}
.meter {{ margin: 28px 0; }}
.bar {{ height: 16px; background: #1a1a1c; border: 1px solid {HEX['steel']}; }}
.fill {{ height: 100%; width: {score}%; background: {fill}; }}
.disclaimer {{ color: {HEX['bone']}; }}
.plates {{ display: flex; gap: 12px; flex-wrap: wrap; }}
.plate {{ flex: 1 1 140px; border: 1px solid #2a2a2c; padding: 10px; min-width: 120px; }}
.plate h2 {{ margin: 0 0 8px; font-size: 13px; color: {HEX['steel']}; }}
.tag {{ font-weight: 700; }}
.intact {{ color: {HEX['steel']}; }}
.scored {{ color: {HEX['bone']}; }}
.broken {{ color: {HEX['blood']}; }}
.unknown {{ color: {HEX['bone']}; }}
footer {{ margin-top: 24px; color: {HEX['steel']}; }}
a {{ color: {HEX['steel']}; }}
"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>SHIELDWALL</title>
<style>{css}</style>
</head>
<body>
<main>
<header>
  <h1>SHIELDWALL</h1>
  <div>host: {host}</div>
</header>
<section class="meter">
  <div class="bar"><div class="fill"></div></div>
  <p>ARMOR {score} { _esc(label) }</p>
  <p class="disclaimer">{_esc(DISCLAIMER)}</p>
</section>
<section class="plates">
{''.join(cards)}
</section>
<ul>{evidence}</ul>
<footer>
  <p>no changes will be applied from this screen</p>
  <p><a href="/api/plates">/api/plates</a></p>
</footer>
</main>
</body>
</html>
"""


def make_handler(provider):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            try:
                report = provider()
            except Exception:
                self.send_error(500, "collect failed")
                return
            if path == "/api/plates":
                body = json.dumps(report).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            elif path in ("/", "/index.html"):
                body = render_html(report).encode("utf-8")
                ctype = "text/html; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return Handler


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _Server6(_Server):
    address_family = 0  # set below


def make_server(host: str, port: int, provider):
    bound = bind_host(host)
    handler = make_handler(provider)
    if ":" in bound:
        import socket

        class Server6(_Server):
            address_family = socket.AF_INET6

        return Server6((bound, port), handler), bound
    return _Server((bound, port), handler), bound


def start_server(host: str, port: int, provider) -> ThreadingHTTPServer:
    httpd, _bound = make_server(host, port, provider)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def serve_blocking(host: str, port: int, provider) -> None:
    httpd, bound = make_server(host, port, provider)
    actual = httpd.server_address[1]
    print(f"shieldwall {format_url(bound, actual)}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
