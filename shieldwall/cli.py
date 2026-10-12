import argparse
import json
import sys

from shieldwall import __version__
from shieldwall.config import load_config, serve_settings
from shieldwall.render import color_enabled, render_text
from shieldwall.report import collect_report
from shieldwall.runner import Runner
from shieldwall.serve import LoopbackRefusal, ensure_loopback, serve_blocking


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shieldwall",
        description="One-screen read-only Linux security dashboard",
    )
    parser.add_argument("--version", action="version", version=f"shieldwall {__version__}")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--config", help="path to config.toml")
    parser.add_argument("--secrets-path", help="path to scan for secrets")
    parser.add_argument("--timeout", type=float, default=5.0, help="collector timeout seconds")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="serve a localhost HTML page and /api/plates")
    serve.add_argument("--host", default=None, help="loopback bind address")
    serve.add_argument("--port", type=int, default=None, help="bind port")
    return parser


def main(argv=None, runner=None, proc_reader=None, log_reader=None, which=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 1
    if args.timeout <= 0:
        print("shieldwall: timeout must be positive", file=sys.stderr)
        return 2
    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"shieldwall: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"shieldwall: config error: {exc}", file=sys.stderr)
        return 2
    if args.secrets_path:
        config.setdefault("secrets", {})
        config["secrets"]["path"] = args.secrets_path
    active = runner if runner is not None else Runner(timeout=args.timeout)
    try:
        if args.command == "serve":
            host, port = serve_settings(config)
            if args.host is not None:
                host = args.host
            if args.port is not None:
                port = args.port
            if not 0 <= port <= 65535:
                print("shieldwall: port out of range", file=sys.stderr)
                return 2
            ensure_loopback(host)
            serve_blocking(
                host,
                port,
                lambda: collect_report(
                    config,
                    active,
                    proc_reader=proc_reader,
                    log_reader=log_reader,
                    which=which,
                ).to_dict(),
            )
            return 0
        report = collect_report(
            config,
            active,
            proc_reader=proc_reader,
            log_reader=log_reader,
            which=which,
        )
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(render_text(report, color=color_enabled(args.no_color)))
        return 0
    except LoopbackRefusal as exc:
        print(f"shieldwall: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


def console_main() -> None:
    raise SystemExit(main())
