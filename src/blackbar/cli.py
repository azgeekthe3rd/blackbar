"""Command line interface.

blackbar scrub app.log                    # clean a file to stdout
kubectl logs pod | blackbar scrub -       # clean a stream
blackbar scan --json diary.txt            # report only, redacted by default
blackbar scan --quiet secrets.env         # exit 1 if anything found (CI guard)
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from collections.abc import Sequence

from . import __version__
from .core import Scrubber
from .redact import STRATEGY_NAMES, build_strategy
from .types import Entity

#: Exit codes, so shell callers can branch without parsing output.
EXIT_OK = 0
EXIT_FOUND = 1
EXIT_USAGE = 2

KEY_ENV_VAR = "BLACKBAR_KEY"


def _entity_list(value: str) -> list[Entity]:
    entities: list[Entity] = []
    for item in value.split(","):
        name = item.strip().upper()
        if not name:
            continue
        try:
            entities.append(Entity[name])
        except KeyError:
            valid = ", ".join(e.value for e in Entity)
            raise argparse.ArgumentTypeError(
                f"unknown entity {name!r}. Choose from: {valid}"
            ) from None
    return entities


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackbar",
        description="Find and redact PII, with checksum validation to cut false positives.",
    )
    parser.add_argument("--version", action="version", version=f"blackbar {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "path",
            nargs="?",
            default="-",
            help="input file, or '-' for stdin (default: stdin)",
        )
        sub.add_argument(
            "--only",
            type=_entity_list,
            metavar="A,B",
            help="restrict detection to these entities",
        )
        sub.add_argument(
            "--exclude",
            type=_entity_list,
            metavar="A,B",
            help="skip these entities",
        )
        sub.add_argument(
            "--allow",
            action="append",
            default=[],
            metavar="VALUE",
            help="literal value to leave untouched (repeatable)",
        )

    scrub_cmd = subcommands.add_parser("scrub", help="write redacted text to stdout")
    add_common(scrub_cmd)
    scrub_cmd.add_argument(
        "-s",
        "--strategy",
        choices=STRATEGY_NAMES,
        default="label",
        help="how to replace matches (default: label)",
    )
    scrub_cmd.add_argument(
        "--keep",
        type=int,
        metavar="N",
        help="with --strategy mask, trailing characters to preserve",
    )
    scrub_cmd.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write to FILE instead of stdout",
    )
    scrub_cmd.add_argument(
        "--stream",
        action="store_true",
        help="process line by line for constant memory; disables multi-line "
        "detection such as PEM private key blocks",
    )

    scan_cmd = subcommands.add_parser("scan", help="report findings without rewriting")
    add_common(scan_cmd)
    scan_cmd.add_argument("--json", action="store_true", help="emit a JSON report")
    scan_cmd.add_argument(
        "--show-values",
        action="store_true",
        help="include the matched text (leaks the secrets you just found)",
    )
    scan_cmd.add_argument("-q", "--quiet", action="store_true", help="suppress output")

    return parser


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _make_scrubber(args: argparse.Namespace) -> Scrubber:
    strategy = build_strategy(
        getattr(args, "strategy", "label"),
        key=os.environ.get(KEY_ENV_VAR),
        keep=getattr(args, "keep", None),
    )
    return Scrubber(
        strategy=strategy,
        only=args.only,
        exclude=args.exclude,
        allowlist=args.allow,
    )


def _run_scrub(args: argparse.Namespace, scrubber: Scrubber) -> int:
    found = False
    with contextlib.ExitStack() as stack:
        out = (
            stack.enter_context(open(args.output, "w", encoding="utf-8"))
            if args.output
            else sys.stdout
        )
        if args.stream and args.path == "-":
            # Constant memory, at the cost of multi-line entities such as PEM blocks.
            for line in sys.stdin:
                result = scrubber.scrub(line)
                found = found or result.found_anything
                out.write(result.text)
        else:
            result = scrubber.scrub(_read(args.path))
            found = result.found_anything
            out.write(result.text)
    return EXIT_FOUND if found else EXIT_OK


def _run_scan(args: argparse.Namespace, scrubber: Scrubber) -> int:
    result = scrubber.scrub(_read(args.path))

    if args.quiet:
        pass
    elif args.json:
        print(json.dumps(result.report(include_text=args.show_values), indent=2))
    elif not result.found_anything:
        print("No PII detected.")
    else:
        width = max(len(name) for name in result.counts)
        for entity, count in result.counts.items():
            print(f"{entity:<{width}}  {count}")
        print(f"{'TOTAL':<{width}}  {len(result.matches)}")

    return EXIT_FOUND if result.found_anything else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        scrubber = _make_scrubber(args)
        if args.command == "scrub":
            return _run_scrub(args, scrubber)
        return _run_scan(args, scrubber)
    except FileNotFoundError as error:
        print(f"blackbar: {error.filename}: no such file", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover - `| head` and friends
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
