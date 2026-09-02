"""Independent tclk/1 frame decoder and verifier — the hash-lock path.

Ported from flop-labs/tclk's src/frames.ts and src/machine.ts (read directly from source,
not from SPEC.md prose), cross-checked against the golden vectors in tests/vectors.test.ts
via examples/hashlock_walkthrough.py (PR #13, unmerged as of this writing) — that walkthrough's
canonical_json/domain_hash/offer_id/contract_id/opens/apply_frame functions are reused here
near-verbatim, since they are already independently reproducible from the reference test
vectors and re-deriving them would just be re-typing already-correct work.

What this module adds on top of that walkthrough, which is a frame *builder* (constructs
well-formed frames) rather than a frame *reader* (must survive arbitrary, possibly hostile
room text): fail-closed decoding of an untrusted `tclk1 ` line, exactly mirroring frames.ts's
`validateFrame` — unknown keys, missing fields, and malformed values reject rather than
coerce, same as the reference implementation.

Point-lock (PTLC) frames decode structurally but are NOT cryptographically verified here.
Reveal-secret verification for a point lock is pure, self-contained math (`verifyPointWitness`
in points.ts: compressed(witness*G) == statement) and could be added with a secp256k1
dependency; `lock` frame `presig` verification additionally needs the rail's own claim-message
construction, which is rail-specific and out of scope for a room-transcript-only verifier.

Known reference-implementation quirks this module deliberately mirrors rather than "fixes",
since the job is checking against what actually ships:
  - tclk issue #22: `SCALAR_HEX` (`^0x[0-9a-f]{1,64}$`) accepts odd-length hex that the
    reference's own hexToU8a rejects downstream. Not applicable to the hash-lock path this
    module covers (secret/statement here are HEX32, always even-length), but noted for when
    the point-lock path is added.
  - tclk issue #17: a `cancel` in `proposed` status never checks `frame["contract"]` against
    anything (there is nothing yet to check against) — so a single cancel frame is ambiguous
    against every pending offer from that sender, not scoped to one. `apply_frame` below
    reproduces this exactly (matching machine.ts), and `verify_transcript` flags it separately
    rather than asserting a clean single-contract verdict.
  - The room-level `reveal` guard is `now < refundAfterMs`, not `claimByMs`. `claimByMs` is
    advisory only — never referenced by machine.ts's transition guards — so a "late" reveal
    per the README's claimByMs sense still transitions to `claimed` at the room level; only
    `refundAfterMs` is a hard rejection boundary. `verify_transcript` reports both boundaries
    separately: `late_past_claim_by` (informational) vs. the hard `refundAfterMs` rejection.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

TCLK_PREFIX = "tclk1 "
TCLK_DOMAIN = "FLOP::tclk::v1"
MAX_FRAME_CHARS = 4096

# ── Field shapes (frames.ts, exact) ──────────────────────────────────────────

HEX32 = re.compile(r"^0x[0-9a-f]{64}$")
HEX33 = re.compile(r"^0x[0-9a-f]{66}$")
DID = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
AMOUNT = re.compile(r"^[1-9][0-9]*$")
ASSET = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
RAIL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NONCE = re.compile(r"^[0-9a-f]{8,64}$")
# SCALAR_HEX (point-lock only, not exercised by the hash-lock path below) — kept here as
# the exact reference regex, odd-length-hex quirk and all (tclk issue #22), for when the
# point-lock path is added: re.compile(r"^0x[0-9a-f]{1,64}$")

TERMINAL_STATUSES = {"claimed", "refunded", "cancelled"}

# Exact allowed/required key sets per frame type, from frames.ts's KEYS table.
FRAME_KEYS: dict[str, dict[str, set[str]]] = {
    "offer": {
        "allowed": {"type", "from", "role", "amount", "asset", "lock", "rails", "claimByMs",
                    "refundAfterMs", "expiresMs", "paymentKey", "job", "nonce", "id"},
        "required": {"from", "role", "amount", "asset", "lock", "rails", "claimByMs",
                     "refundAfterMs", "expiresMs", "nonce", "id"},
    },
    "accept": {
        "allowed": {"type", "from", "ref", "statement", "contract", "paymentKey", "nonce"},
        "required": {"from", "ref", "statement", "contract", "nonce"},
    },
    "lock": {
        "allowed": {"type", "from", "contract", "rail", "ref", "presig"},
        "required": {"from", "contract", "rail", "ref"},
    },
    "reveal": {
        "allowed": {"type", "from", "contract", "secret"},
        "required": {"from", "contract", "secret"},
    },
    "refund": {
        "allowed": {"type", "from", "contract", "reason"},
        "required": {"from", "contract"},
    },
    "cancel": {
        "allowed": {"type", "from", "contract", "reason"},
        "required": {"from", "contract"},
    },
    "receipt": {
        "allowed": {"type", "from", "contract", "outcome", "rail", "ref"},
        "required": {"from", "contract", "outcome"},
    },
}


class TclkDecodeError(Exception):
    """A tclk line failed fail-closed validation. Carries the reason, never coerces."""


def fail(msg: str):
    raise TclkDecodeError(msg)


# ── Canonical encoding (frames.ts: canonicalJson + toAscii) ─────────────────
#
# Verified against tests/vectors.test.ts's golden vectors (offer id, contract id, and the
# non-ASCII-job-field id) via examples/hashlock_walkthrough.py — Python's own
# json.dumps(ensure_ascii=True) emits the same lowercase \uXXXX UTF-16 escapes, surrogate
# pairs included, as JS's JSON.stringify + a manual toAscii pass. Confirmed by running that
# walkthrough directly, not taken on the PR description's word.


def canonical_json(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            if value[key] is None:  # Python's spelling of "undefined: dropped"
                continue
            parts.append(f"{json.dumps(key, ensure_ascii=True)}:{canonical_json(value[key])}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, bool) or value is None:
        fail("frame contains an unsupported value")
    return json.dumps(value, ensure_ascii=True)


def domain_hash(tag: str, payload: str) -> str:
    data = f"{TCLK_DOMAIN}|{tag}|{payload}".encode("ascii")
    return "0x" + hashlib.sha256(data).hexdigest()


def offer_id(fields: dict) -> str:
    without_id = {k: v for k, v in fields.items() if k != "id"}
    return domain_hash("offer", canonical_json(without_id))


def contract_id(offer: dict, accept_core: dict) -> str:
    return domain_hash("contract", canonical_json({"offer": offer, "accept": accept_core}))


# ── Fail-closed decoding, the piece the builder-only walkthrough doesn't need ─


def _require_keys(frame: dict, frame_type: str) -> None:
    keys = FRAME_KEYS.get(frame_type)
    if keys is None:
        fail(f"unknown frame type: {frame_type}")
    unknown = set(frame.keys()) - keys["allowed"]
    if unknown:
        fail(f"unknown field on {frame_type}: {sorted(unknown)[0]}")
    missing = keys["required"] - set(frame.keys())
    if missing:
        fail(f"missing field on {frame_type}: {sorted(missing)[0]}")


def _require_str(frame: dict, name: str, pattern: re.Pattern | None = None) -> str:
    v = frame.get(name)
    if not isinstance(v, str) or v == "":
        fail(f"{name} must be a non-empty string")
    if pattern and not pattern.match(v):
        fail(f"{name} is malformed: {v}")
    return v


def _require_ms(frame: dict, name: str) -> int:
    v = frame.get(name)
    # Python bool is an int subclass; JS's Number.isSafeInteger(true) is false, so exclude it.
    if isinstance(v, bool) or not isinstance(v, int) or v <= 0 or abs(v) > 2**53 - 1:
        fail(f"{name} must be a positive unix-ms integer")
    return v


def decode_frame(text: str) -> dict:
    """Fail-closed decode of one `tclk1 ` room-message line. Raises TclkDecodeError on any
    violation — unknown key, missing field, malformed value — never coerces, mirroring
    frames.ts's validateFrame exactly for the hash-lock-relevant fields.

    Point-lock frames decode (paymentKey/statement shape checked as HEX33, on-curve NOT
    checked — that needs points.ts's isValidPointStatement, a secp256k1 dependency not
    added here) but are flagged by the caller as not cryptographically verified.
    """
    if not text.startswith(TCLK_PREFIX):
        fail("not a tclk/1 line")
    try:
        frame = json.loads(text[len(TCLK_PREFIX):])
    except ValueError:
        fail("frame is not valid JSON")
    if not isinstance(frame, dict):
        fail("frame must be an object")

    frame_type = frame.get("type")
    if not isinstance(frame_type, str):
        fail("missing or non-string type")
    _require_keys(frame, frame_type)
    _require_str(frame, "from", DID)

    if frame_type == "offer":
        if frame.get("role") not in ("payer", "payee"):
            fail("role must be payer|payee")
        _require_str(frame, "amount", AMOUNT)
        _require_str(frame, "asset", ASSET)
        if frame.get("lock") not in ("hash", "point"):
            fail("lock must be hash|point")
        rails = frame.get("rails")
        if not isinstance(rails, list) or not rails:
            fail("rails must be a non-empty array")
        for rail in rails:
            if not isinstance(rail, str) or not RAIL.match(rail):
                fail(f"rail is malformed: {rail!r}")
        claim_by = _require_ms(frame, "claimByMs")
        refund_after = _require_ms(frame, "refundAfterMs")
        _require_ms(frame, "expiresMs")
        if claim_by >= refund_after:
            fail("claimByMs must be strictly before refundAfterMs")
        if frame.get("lock") == "point" and "paymentKey" not in frame:
            fail("point locks require paymentKey")
        if "paymentKey" in frame:
            _require_str(frame, "paymentKey", HEX33)  # shape only; on-curve check omitted
        _require_str(frame, "nonce", NONCE)
        without_id = {k: v for k, v in frame.items() if k != "id"}
        expected = offer_id(without_id)
        if frame.get("id") != expected:
            fail(f"offer id mismatch (expected {expected})")

    elif frame_type == "accept":
        _require_str(frame, "ref", HEX32)
        statement = frame.get("statement")
        if not isinstance(statement, str) or not (HEX32.match(statement) or HEX33.match(statement)):
            fail(f"statement is malformed: {statement!r}")
        _require_str(frame, "contract", HEX32)
        if "paymentKey" in frame:
            _require_str(frame, "paymentKey", HEX33)
        _require_str(frame, "nonce", NONCE)

    elif frame_type == "lock":
        _require_str(frame, "contract", HEX32)
        _require_str(frame, "rail", RAIL)
        _require_str(frame, "ref")
        if "presig" in frame:
            presig = frame["presig"]
            if not isinstance(presig, dict) or set(presig.keys()) - {"nonce", "s"}:
                fail("presig must be an object with only nonce/s")
            if "nonce" not in presig or "s" not in presig:
                fail("presig missing nonce or s")
            if not HEX33.match(presig["nonce"]):
                fail("presig.nonce is malformed")
            # SCALAR_HEX, odd-length-hex quirk included (tclk issue #22) — see module docstring.
            if not re.match(r"^0x[0-9a-f]{1,64}$", presig["s"]):
                fail("presig.s is malformed")

    elif frame_type == "reveal":
        _require_str(frame, "contract", HEX32)
        _require_str(frame, "secret", HEX32)

    elif frame_type in ("refund", "cancel"):
        _require_str(frame, "contract", HEX32)
        if "reason" in frame:
            _require_str(frame, "reason")

    elif frame_type == "receipt":
        _require_str(frame, "contract", HEX32)
        if frame.get("outcome") not in ("claimed", "refunded", "cancelled"):
            fail("outcome must be claimed|refunded|cancelled")
        if "rail" in frame:
            _require_str(frame, "rail", RAIL)
        if "ref" in frame:
            _require_str(frame, "ref")

    else:
        fail(f"unknown frame type: {frame_type}")

    # Re-canonicalize and require the wire bytes to already be canonical — a semantically
    # valid but non-canonically-encoded frame (extra whitespace, unsorted keys) is itself a
    # protocol violation per frames.ts's encodeFrame contract ("the stored bytes equal the
    # signed bytes"), not something to silently accept.
    recanon = TCLK_PREFIX + canonical_json(frame)
    if recanon != text:
        fail("frame is not in canonical form (re-encoding does not match the wire bytes)")

    return frame


def try_decode_frame(text: str) -> dict | None:
    """None for a non-tclk line AND for a malformed tclk line — room text is anonymous
    input, a hostile line must not raise past a polling loop."""
    try:
        return decode_frame(text)
    except TclkDecodeError:
        return None


# ── Hash-lock verification ───────────────────────────────────────────────────


def statement_of(preimage_hex: str) -> str:
    raw = bytes.fromhex(preimage_hex[2:])
    return "0x" + hashlib.sha256(raw).hexdigest()


def opens_hash_lock(statement: str, secret: str) -> bool:
    return bool(HEX32.match(secret)) and statement_of(secret) == statement


# ── State machine (machine.ts, hash-lock path — point-lock statements decode but their
#    reveal is reported as "not cryptographically verified" rather than checked) ────────


@dataclass
class ContractState:
    status: str
    offer: dict
    payer_did: str | None = None
    payee_did: str | None = None
    contract: str | None = None
    statement: str | None = None
    lock_kind: str = "hash"
    rail: str | None = None
    rail_ref: str | None = None
    secret: str | None = None


def open_contract(offer: dict) -> ContractState:
    return ContractState(
        status="proposed",
        offer=offer,
        payer_did=offer["from"] if offer["role"] == "payer" else None,
        payee_did=offer["from"] if offer["role"] == "payee" else None,
        lock_kind=offer["lock"],
    )


def _is_party(state: ContractState, did: str) -> bool:
    return did in (state.offer["from"], state.payer_did, state.payee_did)


def apply_frame(state: ContractState, frame: dict, now_ms: int) -> tuple[ContractState, bool, str]:
    """(next_state, ok, reason). Mirrors machine.ts's applyFrame exactly, including the
    tclk#17 cancel-in-proposed ambiguity and the refundAfterMs-not-claimByMs reveal cutoff —
    see module docstring."""
    frame_type = frame["type"]

    if frame_type == "offer":
        return state, False, "contract is already open"

    if frame_type == "accept":
        if state.status != "proposed":
            return state, False, f"accept in status {state.status}"
        if frame["ref"] != state.offer["id"]:
            return state, False, "accept.ref names a different offer"
        if frame["from"] == state.offer["from"]:
            return state, False, "cannot accept own offer"
        if now_ms >= state.offer["expiresMs"]:
            return state, False, "offer has expired"
        core = {k: frame.get(k) for k in ("from", "ref", "statement", "paymentKey", "nonce")
                if frame.get(k) is not None}
        expected = contract_id(state.offer, core)
        if frame["contract"] != expected:
            return state, False, "contract id mismatch"
        if state.offer["lock"] == "point" and "paymentKey" not in frame:
            return state, False, "point locks require the acceptor's paymentKey"
        statement = frame["statement"]
        fits = HEX32.match(statement) if state.offer["lock"] == "hash" else HEX33.match(statement)
        if not fits:
            return state, False, f"statement does not fit a {state.offer['lock']} lock"
        acceptor_is_payer = state.offer["role"] == "payee"
        new_state = ContractState(
            **{**state.__dict__,
               "status": "accepted",
               "contract": frame["contract"],
               "statement": statement,
               "payer_did": frame["from"] if acceptor_is_payer else state.payer_did,
               "payee_did": state.payee_did if acceptor_is_payer else frame["from"]},
        )
        return new_state, True, "accepted"

    if frame_type == "lock":
        if state.status != "accepted":
            return state, False, f"lock in status {state.status}"
        if frame["contract"] != state.contract:
            return state, False, "lock names a different contract"
        if frame["from"] != state.payer_did:
            return state, False, "only the payer locks"
        if frame["rail"] not in state.offer["rails"]:
            return state, False, f"rail {frame['rail']} was not offered"
        new_state = ContractState(**{**state.__dict__, "status": "locked",
                                      "rail": frame["rail"], "rail_ref": frame["ref"]})
        return new_state, True, "locked"

    if frame_type == "reveal":
        if state.status != "locked":
            return state, False, f"reveal in status {state.status}"
        if frame["contract"] != state.contract:
            return state, False, "reveal names a different contract"
        if frame["from"] != state.payee_did:
            return state, False, "only the payee reveals"
        # Hard cutoff is refundAfterMs, NOT claimByMs — see module docstring.
        if now_ms >= state.offer["refundAfterMs"]:
            return state, False, "refund window is open"
        if state.lock_kind == "hash":
            if not opens_hash_lock(state.statement, frame["secret"]):
                return state, False, "secret does not open the statement"
        else:
            return state, False, "point-lock reveal: not cryptographically verified here"
        new_state = ContractState(**{**state.__dict__, "status": "claimed",
                                      "secret": frame["secret"]})
        return new_state, True, "claimed (terminal)"

    if frame_type == "refund":
        if state.status != "locked":
            return state, False, f"refund in status {state.status}"
        if frame["contract"] != state.contract:
            return state, False, "refund names a different contract"
        if frame["from"] != state.payer_did:
            return state, False, "only the payer refunds"
        if now_ms < state.offer["refundAfterMs"]:
            return state, False, "refund window not open yet"
        new_state = ContractState(**{**state.__dict__, "status": "refunded"})
        return new_state, True, "refunded (terminal)"

    if frame_type == "cancel":
        if state.status not in ("proposed", "accepted"):
            return state, False, f"cancel in status {state.status}"
        # tclk#17: no frame["contract"] check in "proposed" — nothing to compare against yet.
        # Ambiguous-cancel flagging happens one level up, in verify_transcript.
        if state.status == "accepted" and frame["contract"] != state.contract:
            return state, False, "cancel names a different contract"
        if not _is_party(state, frame["from"]):
            return state, False, "cancel from a non-party"
        new_state = ContractState(**{**state.__dict__, "status": "cancelled"})
        return new_state, True, "cancelled (terminal)"

    if frame_type == "receipt":
        if state.status not in TERMINAL_STATUSES:
            return state, False, "receipt before a terminal status"
        if frame["contract"] != state.contract:
            return state, False, "receipt names a different contract"
        if not _is_party(state, frame["from"]):
            return state, False, "receipt from a non-party"
        if frame["outcome"] != state.status:
            return state, False, f"receipt outcome {frame['outcome']} does not match {state.status}"
        return state, True, "receipt acknowledged (no transition)"

    return state, False, f"unknown frame type: {frame_type}"
