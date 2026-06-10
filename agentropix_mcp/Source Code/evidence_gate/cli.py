"""Command-line interface for the Step-2 evidence gate.

Usage:
  python -m agentropix_mcp.evidence_gate.cli mint --ttl 3600 --scope wazuh.publish_iocs
  python -m agentropix_mcp.evidence_gate.cli verify --token egt_X --op wazuh.publish_iocs
  python -m agentropix_mcp.evidence_gate.cli revoke --token egt_X
  python -m agentropix_mcp.evidence_gate.cli revoke-by-id --token-id <ULID>
  python -m agentropix_mcp.evidence_gate.cli list [--scope X] [--no-spent] ...

Used by validation-plan v3 layers L3.2 (mint) and L6 (revoke).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .errors import RegistryUnavailable, TokenError
from .registry import TokenRegistry

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--db",
        help="Override registry DB path "
             "(default: $AGENTROPIX_EVIDENCE_GATE_DB or ~/.agentropix/evidence-gate.sqlite)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress info logging",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    mint_p = sub.add_parser("mint", help="Mint a new token")
    mint_p.add_argument("--scope", required=True,
                        help="Operation scope (e.g. wazuh.publish_iocs)")
    mint_p.add_argument("--ttl", type=int, required=True,
                        help="TTL in seconds (max 604800 = 7d)")
    mint_p.add_argument("--operator",
                        help="Operator name (default: $USER)")
    mint_p.add_argument("--emit", choices=("token", "json"), default="token",
                        help="Output format (default: token; prints just the secret on stdout)")

    verify_p = sub.add_parser("verify", help="Verify+spend a token (atomic)")
    verify_p.add_argument("--token", required=True)
    verify_p.add_argument("--op", required=True,
                          help="Operation scope (must match the scope at mint)")
    verify_p.add_argument("--run-id",
                          help="Run identifier to record alongside the spend")
    verify_p.add_argument("--emit", choices=("json", "human"), default="json")

    rev_p = sub.add_parser("revoke", help="Revoke a token by full secret")
    rev_p.add_argument("--token", required=True)

    rev_id_p = sub.add_parser("revoke-by-id",
                              help="Revoke by token_id (no secret needed; emergency use)")
    rev_id_p.add_argument("--token-id", required=True,
                          help="The 26-char base32 ULID portion of the token")

    list_p = sub.add_parser("list", help="List tokens (operator-only)")
    list_p.add_argument("--scope")
    list_p.add_argument("--no-spent", action="store_true")
    list_p.add_argument("--no-revoked", action="store_true")
    list_p.add_argument("--no-expired", action="store_true")
    list_p.add_argument("--emit", choices=("json", "human"), default="human")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    db_path = Path(args.db) if args.db else None

    try:
        registry = TokenRegistry(db_path=db_path)
    except RegistryUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        if args.cmd == "mint":
            import os as _os
            operator = args.operator or _os.environ.get("USER") or _os.environ.get("USERNAME")
            token = registry.mint(
                scope=args.scope,
                ttl_seconds=args.ttl,
                operator=operator,
            )
            if args.emit == "token":
                # Print ONLY the bearer secret on stdout so it can be captured
                # via $(...). Logging metadata goes to stderr.
                sys.stdout.write(token)
                sys.stdout.write("\n")
            else:
                token_id = token[len("egt_"):]
                json.dump(
                    {"token": token, "token_id": token_id,
                     "scope": args.scope, "ttl_seconds": args.ttl,
                     "operator": operator},
                    sys.stdout,
                )
                sys.stdout.write("\n")
            return 0

        if args.cmd == "verify":
            row = registry.verify_and_spend(
                args.token, op=args.op, run_id=args.run_id,
            )
            payload = {
                "verified": True, "spent": True,
                "token_id": row.token_id, "scope": row.scope,
                "spent_run_id": row.spent_run_id,
            }
            if args.emit == "json":
                json.dump(payload, sys.stdout)
                sys.stdout.write("\n")
            else:
                print(f"OK token_id={row.token_id} scope={row.scope}")
            return 0

        if args.cmd == "revoke":
            ok = registry.revoke(args.token)
            if ok:
                print("revoked")
                return 0
            print("not-found", file=sys.stderr)
            return 1

        if args.cmd == "revoke-by-id":
            ok = registry.revoke_by_id(args.token_id)
            if ok:
                print("revoked")
                return 0
            print("not-found", file=sys.stderr)
            return 1

        if args.cmd == "list":
            rows = registry.list_tokens(
                scope=args.scope,
                include_spent=not args.no_spent,
                include_revoked=not args.no_revoked,
                include_expired=not args.no_expired,
            )
            import time
            now = time.time()
            if args.emit == "json":
                json.dump(
                    [
                        {
                            "token_id": r.token_id, "scope": r.scope,
                            "created_ts": r.created_ts, "ttl_seconds": r.ttl_seconds,
                            "spent_ts": r.spent_ts, "spent_run_id": r.spent_run_id,
                            "revoked_ts": r.revoked_ts, "operator": r.operator,
                            "status": r.status(now),
                        }
                        for r in rows
                    ],
                    sys.stdout,
                )
                sys.stdout.write("\n")
            else:
                for r in rows:
                    print(
                        f"{r.status(now):8s} {r.token_id} scope={r.scope} "
                        f"ttl={r.ttl_seconds}s operator={r.operator or '-'} "
                        f"spent_run_id={r.spent_run_id or '-'}"
                    )
            return 0

    except TokenError as exc:
        msg = f"{type(exc).__name__}: {exc}"
        if getattr(args, "emit", None) == "json":
            json.dump({"error": msg, "kind": type(exc).__name__}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1
    except RegistryUnavailable as exc:
        print(f"ERROR registry unavailable: {exc}", file=sys.stderr)
        return 2
    finally:
        registry.close()

    return 2  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())
