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


VERSION = "0.2.0"
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

    def read(self) -> tuple[int, int | None] | None:
        """(seq, generation) if a cursor exists, else None for a first run.

        generation is None specifically when reading a cursor written by this tool's
        older, seq-only format: there is no prior generation to compare against yet,
        so the next poll establishes a baseline instead of reporting a spurious reset.
        """
        if not self.path.exists():
            return None
        text = self.path.read_text(encoding="utf-8").strip()
        if not text:
            return None
        lines = text.splitlines()
        try:
            seq = int(lines[0])
            generation = int(lines[1]) if len(lines) > 1 else None
        except ValueError:
            # Fail loud, not silently restart from scratch: treating this as "no cursor"
            # would quietly re-run the first-run capture and duplicate everything already
            # archived, with no sign anything went wrong. A corrupted cursor needs a human,
            # not a guess.
            raise SystemExit(
                f"cursor file {self.path} contains {text!r} — expected a sequence number "
                "and optionally a generation on the line after it. Fix or delete it by "
                "hand before running again"
            ) from None
        return seq, generation

    def write(self, seq: int, generation: int | None) -> None:
        body = str(seq) if generation is None else f"{seq}\n{generation}"
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(body, encoding="utf-8")
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


def run(args: argparse.Namespace) -> None:
    out_path = Path(args.out)
    cursor = Cursor(Path(args.cursor_file))
    state = cursor.read()
    first_run = state is None
    last_seq, last_generation = state if state is not None else (None, None)

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
        generation = view.get("generation")

        if first_run:
            append_jsonl(
                out_path,
                {
                    "event": "archive_start",
                    "room": args.room,
                    "first_observed_seq": first_seq,
                    "first_observed_generation": generation,
                    "detected_at": time.time(),
                    "note": (
                        "nothing before this seq in this room was ever observed by this "
                        "tool and it is not recoverable"
                    ),
                },
            )
            first_run = False
        elif messages and first_seq is not None and last_seq is not None and first_seq > last_seq + 1:
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

        # technocore-chat computes `generation` for every room read, including an empty
        # one (#139 dir #3) — an explicit, authoritative signal that this room was reaped
        # and recreated since our last poll. This replaces the probe-and-guess this tool
        # used before that field existed: no extra request, and no ambiguity about
        # whether an empty response means "quiet" or "your cursor is stale." The floor
        # bump that ships alongside it (#139 dir #2) keeps `since` valid across the
        # transition, so nothing needs re-fetching here — this only records that the
        # discontinuity happened. `last_generation is None` exclusively means "upgraded
        # from an older cursor that never tracked this," not "no reset": that first
        # observation is a baseline, not a transition, so it is deliberately not compared.
        if last_generation is not None and generation is not None and generation != last_generation:
            reset_event = {
                "event": "room_reset",
                "room": args.room,
                "old_generation": last_generation,
                "new_generation": generation,
                "cursor_at_reset": last_seq,
                "detected_at": time.time(),
                "note": (
                    "technocore-chat's own generation counter changed: this room was "
                    "reaped and recreated. Its seq floor keeps `since` valid across "
                    "the transition, so no messages are skipped here — this event "
                    "only marks the discontinuity"
                ),
            }
            append_jsonl(out_path, reset_event)
            print(
                f"[archiver] ROOM RESET: generation {last_generation} -> {generation}",
                file=sys.stderr,
            )
        last_generation = generation

        archive_messages(out_path, args.room, messages)

        # Only an actual message tells the truth about last_seq here: when `messages` is
        # empty, view["last_seq"] is the since= value echoed back by technocore-chat's
        # read_messages() when nothing matches the filter, not a real measurement.
        if messages and "last_seq" in view:
            last_seq = view["last_seq"]

        if last_seq is not None:
            cursor.write(last_seq, last_generation)

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
