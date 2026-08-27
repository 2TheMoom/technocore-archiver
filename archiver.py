#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography==50.0.0"]
# ///
"""Verify-then-archive watcher for a technocore.chat room.

Why this exists: a message is fetchable via `?since=&limit=&format=json` only while it
sits within the newest 200 records *or* the newest 1 MiB of the room file (whichever the
tip reaches first) — see read_messages()/reverse_lines() in technocore-chat's own
src/store.py. That window is measured from wherever the tip currently is, not from where
a message was written, so every message anyone else posts pushes older ones closer to
eviction. Once a message crosses either boundary it is permanently unfetchable — there is
no `before=` parameter and no export/admin endpoint.

This tool polls a room, verifies each signed message's Ed25519 signature independently
(never trusting the server's word that verification happened at write time), and appends
the result to durable local storage before that window closes. It does NOT and cannot
recover anything already evicted before it starts watching — see --help and README.md.

did:key parsing (verify_did_key below) is adapted from technocore-chat's src/didkey.py
(Apache-2.0, github.com/flop-labs/technocore-chat) — a small, self-contained
implementation worth reusing correctly rather than reinventing base58btc decoding.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ── did:key (Ed25519) verification — adapted from technocore-chat's src/didkey.py ──

DID_PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_CHARS = 48
SIG_CHARS = 86
SIG_RE = re.compile(rf"[A-Za-z0-9_-]{{{SIG_CHARS}}}")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


class DidKeyError(ValueError):
    """A malformed did:key, or a signature that does not verify."""


def _b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise DidKeyError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def did_public_key(did: str) -> bytes:
    """The 32 raw Ed25519 public-key bytes of a did:key, or raise DidKeyError."""
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise DidKeyError(f"bad did:key: expected {DID_PREFIX}z6Mk...")
    mb = did[len(DID_PREFIX) :]
    if len(mb) != MULTIBASE_CHARS or not mb.startswith("z"):
        raise DidKeyError(f"bad did:key: expected {MULTIBASE_CHARS} multibase chars")
    decoded = _b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise DidKeyError("bad did:key: only ed25519-pub (z6Mk...) keys are accepted")
    return decoded[2:]


def verify_signature(did: str, signature: str, message: str) -> bool:
    """True iff `signature` is `did`'s Ed25519 signature over `message` (UTF-8).

    Never raises for a bad-but-well-formed signature — returns False. Raises DidKeyError
    only for a malformed did:key or malformed signature encoding, which the caller treats
    as a distinct failure mode (a record that doesn't even parse, not one that fails
    cryptographic verification).
    """
    key = Ed25519PublicKey.from_public_bytes(did_public_key(did))
    if not SIG_RE.fullmatch(signature or ""):
        raise DidKeyError(f"bad signature encoding: expected {SIG_CHARS} base64url chars")
    raw = base64.urlsafe_b64decode(signature[:SIG_CHARS] + "==")
    try:
        key.verify(raw, message.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


# ── HTTP ──


VERSION = "0.1.0"
USER_AGENT = f"technocore-archiver/{VERSION} (+https://github.com/2TheMoom/technocore-archiver)"


def fetch_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


# ── archiver ──


@dataclass
class Cursor:
    path: Path

    def read(self) -> int | None:
        if not self.path.exists():
            return None
        text = self.path.read_text(encoding="utf-8").strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            # Fail loud, not silently restart from scratch: treating this as "no cursor"
            # would quietly re-run the first-run capture and duplicate everything already
            # archived, with no sign anything went wrong. A corrupted cursor needs a human,
            # not a guess.
            raise SystemExit(
                f"cursor file {self.path} contains {text!r}, not a sequence number — fix "
                "or delete it by hand before running again"
            ) from None

    def write(self, seq: int) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(str(seq), encoding="utf-8")
        tmp.replace(self.path)  # atomic on both POSIX and Windows


def classify(room: str, message: dict) -> str:
    """One of: verified, failed, sig-missing, unsigned, malformed."""
    nonce = message.get("nonce")
    sig = message.get("sig")
    did = message.get("from")
    if nonce is None:
        return "unsigned"
    if sig is None:
        return "sig-missing"  # signed at write time, but server predates #68's fix
    canonical = f"{room}|{nonce}|{message.get('text', '')}"
    try:
        return "verified" if verify_signature(did, sig, canonical) else "failed"
    except DidKeyError:
        return "malformed"


def append_jsonl(path: Path, record: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def archive_messages(out_path: Path, room: str, messages: list[dict]) -> None:
    for message in messages:
        status = classify(room, message)
        append_jsonl(out_path, {**message, "_status": status, "_archived_at": time.time()})
        if status in ("failed", "malformed"):
            print(f"[archiver] seq {message.get('seq')}: {status}", file=sys.stderr)


def check_for_room_reset(
    base_url: str, room: str, cursor_seq: int, wait: float
) -> tuple[dict, list[dict]] | None:
    """A (room_reset event, any messages already in the new room) pair if an
    unconditional read proves `cursor_seq` is now stale, else None.

    Only an unconditional read (no since=) can tell: technocore-chat's read_messages()
    echoes `since` straight back as `last_seq` when nothing matches the filter (its own
    src/store.py), so a genuinely quiet room and a room whose seq counter reset both
    produce byte-identical `?since=<cursor>` responses. Reads with the same limit=200
    the main loop uses, not limit=1, so a room that already has activity by the time
    this notices the reset is captured from here instead of silently skipped — a
    limit=1 probe would prove the reset but then jump straight to the newest message,
    losing anything between the new room's start and that point with no gap ever
    recorded for it either. Returns None on a fetch failure too — this is a
    best-effort confirmation, not the main read path, and a transient failure here
    should not interrupt polling.
    """
    try:
        probe = fetch_json(f"{base_url}/r/{room}?limit=200&format=json", timeout=wait + 15)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        print(f"[archiver] reset probe failed, will retry next poll: {exc}", file=sys.stderr)
        return None
    true_last = probe.get("last_seq")
    if true_last is None or true_last >= cursor_seq:
        return None
    event = {
        "event": "room_reset",
        "room": room,
        "old_cursor": cursor_seq,
        "new_first_seq": probe.get("first_seq"),
        "new_last_seq": true_last,
        "detected_at": time.time(),
        "note": (
            "this room's last_seq is now lower than our cursor, almost certainly reaped "
            "and recreated; everything at or before old_cursor is unrecoverable. Any "
            "messages already in the new room by the time this was noticed are archived "
            "alongside this event, not skipped"
        ),
    }
    return event, probe.get("messages", [])


def run(args: argparse.Namespace) -> None:
    out_path = Path(args.out)
    cursor = Cursor(Path(args.cursor_file))
    last_seq = cursor.read()
    first_run = last_seq is None

    print(f"[archiver] room={args.room!r} base={args.base_url} out={out_path}", file=sys.stderr)

    while True:
        if first_run:
            url = f"{args.base_url}/r/{args.room}?limit=200&format=json"
        else:
            # limit=200 explicitly: the server defaults to 50 (app.py's `_cursor(q.get("limit"), 50)`)
            # when the param is omitted, which would shrink this tool's own read window to a
            # quarter of what's actually available and manufacture gaps that didn't need to happen.
            url = f"{args.base_url}/r/{args.room}?since={last_seq}&wait={args.wait}&limit=200&format=json"

        try:
            view = fetch_json(url, timeout=args.wait + 15)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            print(f"[archiver] fetch failed, retrying in 5s: {exc}", file=sys.stderr)
            time.sleep(5)
            continue

        messages = view.get("messages", [])
        first_seq = view.get("first_seq")

        if first_run:
            append_jsonl(
                out_path,
                {
                    "event": "archive_start",
                    "room": args.room,
                    "first_observed_seq": first_seq,
                    "detected_at": time.time(),
                    "note": (
                        "nothing before this seq in this room was ever observed by this "
                        "tool and it is not recoverable"
                    ),
                },
            )
            first_run = False
        elif messages and first_seq is not None and first_seq > last_seq + 1:
            gap = {
                "event": "gap",
                "room": args.room,
                "from_seq": last_seq + 1,
                "to_seq": first_seq - 1,
                "detected_at": time.time(),
                "note": "these seqs aged out of the read window before this tool polled again",
            }
            append_jsonl(out_path, gap)
            print(f"[archiver] GAP: seq {gap['from_seq']}..{gap['to_seq']} unrecoverable", file=sys.stderr)
        elif not messages:
            # See check_for_room_reset()'s docstring for why an empty response can't
            # answer this on its own.
            reset_result = check_for_room_reset(args.base_url, args.room, last_seq, args.wait)
            if reset_result is not None:
                reset_event, reset_messages = reset_result
                append_jsonl(out_path, reset_event)
                print(
                    f"[archiver] ROOM RESET: cursor {last_seq} -> {reset_event['new_last_seq']}"
                    " (room was almost certainly reaped and recreated)",
                    file=sys.stderr,
                )
                archive_messages(out_path, args.room, reset_messages)
                last_seq = reset_event["new_last_seq"]
                cursor.write(last_seq)

        archive_messages(out_path, args.room, messages)

        # Only an actual message tells the truth about last_seq here: when `messages` is
        # empty, view["last_seq"] is the since= value echoed back (see
        # check_for_room_reset()'s docstring), not a real measurement, and writing it
        # would silently undo a reset correction made above in the same iteration.
        if messages and "last_seq" in view:
            last_seq = view["last_seq"]
            cursor.write(last_seq)

        if not args.once:
            continue
        break


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--room", required=True, help="room name, e.g. lobby")
    parser.add_argument("--out", required=True, help="JSONL output file (appended to)")
    parser.add_argument(
        "--cursor-file",
        default=None,
        help="tracks progress across restarts (default: <out>.cursor)",
    )
    parser.add_argument("--base-url", default="https://technocore.chat")
    parser.add_argument(
        "--wait",
        type=float,
        default=10.0,
        help="long-poll seconds per request (technocore.chat's own default cap is 10; a "
        "higher value is silently clamped server-side, not rejected, but won't do anything)",
    )
    parser.add_argument("--once", action="store_true", help="poll once and exit, instead of looping")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.cursor_file is None:
        args.cursor_file = str(Path(args.out).with_suffix(Path(args.out).suffix + ".cursor"))
    try:
        run(args)
    except KeyboardInterrupt:
        print("\n[archiver] stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
