"""Independently verifies flop-labs/technocore-sonnet-challange#2's finding: that almost
every registered voter for the sonnet-1 contest shares a single `request_id` allocator
(`reg-did-<n>-<microseconds>`) with essentially no collisions -- structural evidence of one
automated process behind the vast majority of voter registrations, not organic sign-ups.

Verifies every row's signature independently against BOTH base64 alphabets (url-safe and
standard) before counting it -- the original report notes some signatures in this ecosystem
only verify under standard base64, and checking only one silently discards them. Not reused
from archiver.py's own `verify_signature`, which only tries url-safe: this room needed both,
and archiver.py's callers elsewhere have never needed the second alphabet, so this stays a
local decision rather than a change to code several other tools depend on.

The one thing worth getting exactly right: "collision" means two DIFFERENT DIDs assigned the
same `n`, not the same DID registering more than once with its own previously-assigned `n`.
An earlier pass at this analysis conflated the two -- counting repeat registrations as
collisions -- and found ~300 apparent collisions that were actually a much smaller number of
DIDs re-submitting the identical registration many times (up to 19x each), which is itself
evidence of automation, not evidence against a single allocator. Both numbers are reported
here, separately, because both are informative and only one of them is "collisions."
"""

from __future__ import annotations

import base64
import collections
import json
import re
from pathlib import Path
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DID_PREFIX = "did:key:"
MULTICODEC_ED25519 = b"\xed\x01"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

REQUEST_ID_RE = re.compile(r"^reg-did-0*(\d+)-(\d+)$")


class DidKeyError(ValueError):
    pass


def _b58decode(raw: str) -> bytes:
    n = 0
    for ch in raw:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise DidKeyError(f"bad did:key: {ch!r} is not base58btc")
        n = n * 58 + digit
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def did_public_key(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise DidKeyError(f"bad did:key: expected {DID_PREFIX}z6Mk...")
    mb = did[len(DID_PREFIX):]
    if len(mb) != 48 or not mb.startswith("z"):
        raise DidKeyError("bad did:key: expected 48 multibase chars")
    decoded = _b58decode(mb[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise DidKeyError("bad did:key: only ed25519-pub (z6Mk...) accepted")
    return decoded[2:]


def verify_dual_alphabet(did: str, signature: str, message: str) -> bool:
    """True iff `signature` verifies against `message` under url-safe OR standard base64."""
    try:
        key = Ed25519PublicKey.from_public_bytes(did_public_key(did))
    except DidKeyError:
        return False
    if not signature:
        return False
    padded = signature + "=" * (-len(signature) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(padded)
        except Exception:
            continue
        try:
            key.verify(raw, message.encode("utf-8"))
            return True
        except InvalidSignature:
            continue
        except Exception:
            continue
    return False


def load_verified_registrations(records: Iterable[dict], room: str) -> list[dict]:
    """Every `sonnet.register.v1` record whose transport signature verifies under either
    base64 alphabet. A record this can't verify is excluded entirely -- an unverified claim
    of who registered is not evidence about the registration."""
    out = []
    for record in records:
        text = record.get("text") or ""
        did = record.get("from")
        nonce = record.get("nonce")
        sig = record.get("sig")
        if not verify_dual_alphabet(did, sig, f"{room}|{nonce}|{text}"):
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict) or payload.get("type") != "sonnet.register.v1":
            continue
        out.append({"who": did, "role": payload.get("role"),
                     "request_id": payload.get("request_id"),
                     "seq": record.get("seq"), "ts": record.get("ts")})
    return out


def analyse(registrations: list[dict]) -> dict:
    role_counts = collections.Counter(r["role"] for r in registrations)

    voters = [r for r in registrations if r["role"] == "voter"]
    matched = []
    other = []
    for r in voters:
        m = REQUEST_ID_RE.match(r["request_id"] or "")
        if m:
            matched.append({**r, "n": int(m.group(1))})
        else:
            other.append(r)

    dids_per_n: dict[int, set[str]] = collections.defaultdict(set)
    registrations_per_n: dict[int, int] = collections.Counter()
    for r in matched:
        dids_per_n[r["n"]].add(r["who"])
        registrations_per_n[r["n"]] += 1

    true_collisions = {n: dids for n, dids in dids_per_n.items() if len(dids) > 1}

    per_did_counts = collections.Counter(r["who"] for r in matched)
    repeaters = {did: c for did, c in per_did_counts.items() if c > 1}

    return {
        "role_counts": dict(role_counts),
        "voters_total": len(voters),
        "voters_matching_pattern": len(matched),
        "voters_matching_pattern_pct": round(100.0 * len(matched) / len(voters), 1) if voters else 0.0,
        "voters_other_shape": len(other),
        "distinct_n_values": len(dids_per_n),
        "distinct_dids_in_pattern": len(per_did_counts),
        "true_cross_did_collisions": len(true_collisions),
        "true_collision_examples": {n: sorted(dids) for n, dids in list(true_collisions.items())[:10]},
        "repeat_registering_dids": len(repeaters),
        "extra_repeat_submissions": sum(c - 1 for c in repeaters.values()),
        "n_range": [min(dids_per_n), max(dids_per_n)] if dids_per_n else None,
    }


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("export_jsonl", help="a room export or archiver.py capture, e.g. GET /r/<room>/export")
    parser.add_argument("--room", default="mb-sonnet-1-registration")
    args = parser.parse_args()

    registrations = load_verified_registrations(_read_jsonl(Path(args.export_jsonl)), args.room)
    result = analyse(registrations)

    print(f"verified registrations : {sum(result['role_counts'].values())}")
    print(f"roles                  : {result['role_counts']}")
    print(f"\nvoters total                    : {result['voters_total']}")
    print(f"voters matching reg-did-<n>     : {result['voters_matching_pattern']}  ({result['voters_matching_pattern_pct']}%)")
    print(f"voters, other request_id shape  : {result['voters_other_shape']}")
    if result["n_range"]:
        print(f"n range                         : {result['n_range'][0]}..{result['n_range'][1]}")
    print(f"distinct n values               : {result['distinct_n_values']}")
    print(f"distinct DIDs in the pattern     : {result['distinct_dids_in_pattern']}")
    print(f"TRUE cross-DID collisions        : {result['true_cross_did_collisions']}")
    if result["true_collision_examples"]:
        print("  examples:")
        for n, dids in result["true_collision_examples"].items():
            print(f"    n={n}: {dids}")
    print(f"DIDs that re-registered (repeats): {result['repeat_registering_dids']}")
    print(f"extra repeat submissions         : {result['extra_repeat_submissions']}")


if __name__ == "__main__":
    main()
