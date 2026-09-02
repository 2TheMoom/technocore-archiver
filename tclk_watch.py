#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography==50.0.0"]
# ///
"""Independent, continuous tclk/1 deal verifier — an extension of technocore-archiver.

Watches technocore.chat's public `tclk-offers` board for offer/accept frames, derives each
accepted deal's mailbox room (`mb-p-tclk-<contract prefix>`, per SPEC.md §2), and spawns an
independent long-poll watcher for it — replaying every frame through tclk_verify's ported
state machine and reporting every check it fails, the same "trust nothing but the math"
ethos archiver.py already applies to transport signatures, one layer up.

Two-tier room topology (why this isn't a single-room loop like archiver.py's own run()):
offer and accept both live in tclk-offers; everything from lock onward moves to a room
neither side chose, derived from the contract id. A deal can't be watched by pointing at
one fixed --room — this has to discover deal rooms as they're born and watch each one on
its own long-poll, independently of the others and of the offers board.

Only the hash-lock path is cryptographically verified. A point-lock (PTLC) frame decodes
and replays through the state machine structurally, but its reveal is reported as
`"not cryptographically verified"` rather than checked — see tclk_verify.py's docstring for
why (needs a secp256k1 dependency this tool doesn't carry) and lock frame `presig` is not
checked at all (needs the rail's own claim-message construction, out of scope for a
room-transcript-only verifier).

Frame-`from` binding (SPEC.md §2): "an unsigned frame is data, not a commitment — readers
ignore it." Concretely: a tclk frame is only processed at all if the room message carrying
it has `_status == "verified"` (archiver.py's own transport-signature check) AND the frame's
own internal `from` field matches that verified transport signer. Either failing means the
line is decoded (if it parses) purely for visibility and flagged, never fed into a
contract's state machine.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import archiver as base  # fetch_json, verify_signature, did_public_key, DidKeyError, Cursor, append_jsonl
import tclk_verify as tv

TCLK_OFFERS_ROOM = "tclk-offers"


def deal_room_name(contract: str) -> str:
    """mb-p-tclk-<first 16 hex of the contract id, no 0x>, per SPEC.md §2."""
    hexpart = contract[2:] if contract.startswith("0x") else contract
    return f"mb-p-tclk-{hexpart[:16]}"


# ── Shared, thread-safe sinks ─────────────────────────────────────────────────


class OutputSink:
    """One JSONL file, written from multiple room-watcher threads. archiver.py's own
    append_jsonl assumes single-threaded use; this adds the lock that sharing it needs."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        with self._lock:
            base.append_jsonl(self.path, record)


class ContractRegistry:
    """Durable index of every contract this tool has seen: offer_id, current status, and
    which deal room it lives in — so a restart resumes every non-terminal deal without
    re-scanning tclk-offers from the beginning. Not a cursor by itself; each deal room still
    keeps its own archiver.Cursor for `since=`/generation tracking.

    One JSON object, rewritten atomically on every change (small: one entry per contract
    this tool has ever watched, not per message) — simplicity over a database for a v1.
    """

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._contracts: dict[str, dict] = {}
        if path.exists():
            try:
                self._contracts = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                raise SystemExit(
                    f"contract registry {path} is corrupt — fix or delete it by hand "
                    "before running again (same policy as a corrupt cursor file)"
                ) from None

    def _flush(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._contracts, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def known_offers(self) -> dict[str, dict]:
        with self._lock:
            return {c: v["offer"] for c, v in self._contracts.items() if "offer" in v}

    def pending(self) -> list[tuple[str, dict]]:
        """(contract, entry) for every contract not yet in a terminal status — what a
        restart needs to re-spawn watchers for."""
        with self._lock:
            return [(c, v) for c, v in self._contracts.items()
                    if v.get("status") not in tv.TERMINAL_STATUSES]

    def record_accept(self, contract: str, offer: dict, accept: dict, accept_ts, room: str) -> bool:
        """True if this is a newly discovered contract (caller should spawn a watcher).

        Stores the accept frame alongside the offer, not just the offer: a deal room never
        contains its own accept (SPEC.md §2 — accept lives in tclk-offers, only lock onward
        moves to the derived room), so reconstructing state on spawn or restart means
        replaying open_contract(offer) -> apply_frame(accept), never hand-setting `status`.
        """
        with self._lock:
            if contract in self._contracts:
                return False
            self._contracts[contract] = {
                "offer": offer, "accept": accept, "accept_ts": accept_ts,
                "status": "accepted", "room": room, "discovered_at": time.time(),
            }
            self._flush()
            return True

    def update_status(self, contract: str, status: str) -> None:
        with self._lock:
            if contract in self._contracts:
                self._contracts[contract]["status"] = status
                self._flush()


# ── Per-contract frame processing ─────────────────────────────────────────────


def process_message(
    room: str, message: dict, state: tv.ContractState | None, sink: OutputSink,
) -> tv.ContractState | None:
    """Verify one room message's transport signature, decode+verify any tclk frame in it,
    replay it against `state` if one is open, and write the result. Returns the (possibly
    updated) contract state — None if no contract is open yet (still in tclk-offers,
    pre-accept) or the frame didn't touch it.
    """
    text = message.get("text", "")
    record: dict = {"room": room, "seq": message.get("seq"), "ts": message.get("ts"),
                     "from": message.get("from")}

    # Transport verification first — archiver.py's own signature check, independent of
    # anything tclk-specific.
    transport_status = base.classify(room, message)
    record["_status"] = transport_status

    if not text.startswith(tv.TCLK_PREFIX):
        return state  # ordinary room chatter; nothing to record here

    tclk: dict = {}
    frame = None
    try:
        frame = tv.decode_frame(text)
        tclk["frame_type"] = frame.get("type")
        tclk["decode_ok"] = True
    except tv.TclkDecodeError as exc:
        tclk["decode_ok"] = False
        tclk["decode_error"] = str(exc)

    if frame is not None:
        transport_from = message.get("from")
        tclk["from_matches_transport"] = (
            transport_status == "verified" and frame.get("from") == transport_from
        )
        # SPEC.md §2: "an unsigned frame is data, not a commitment — readers ignore it."
        # Decoded and reported either way, but never fed into a contract's state machine.
        if tclk["from_matches_transport"]:
            if frame["type"] == "accept":
                tclk["contract"] = frame.get("contract")
            elif "contract" in frame:
                tclk["contract"] = frame["contract"]

            if state is not None:
                was_proposed_cancel = frame["type"] == "cancel" and state.status == "proposed"
                new_state, ok, note = tv.apply_frame(state, frame, _ms(message.get("ts")))
                tclk["state_machine"] = note
                tclk["state_machine_ok"] = ok
                if was_proposed_cancel and ok:
                    # tclk issue #17: a proposed-state cancel never checks frame["contract"]
                    # (there is nothing yet to compare against), so this same frame would
                    # equally have cancelled every other pending offer from this sender —
                    # ok=True here is real, but it is not scoped to only this contract.
                    tclk["note"] = ("ambiguous per tclk issue #17: this cancel names no "
                                     "offer while proposed, so it is not scoped to this "
                                     "contract alone")
                if ok:
                    state = new_state
        else:
            tclk["note"] = "frame from does not match the verified transport signer; ignored"

    record["_tclk"] = tclk
    record["_archived_at"] = time.time()
    sink.write(record)
    return state


def _ms(ts) -> int:
    """technocore ts is ISO-8601; tclk deadlines are unix-ms. Best-effort parse — a
    malformed ts fails the frame's timing guards closed (very large now_ms), never open."""
    if isinstance(ts, (int, float)):
        return int(ts)
    try:
        import datetime

        return int(datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000)
    except (ValueError, TypeError):
        return 2**53 - 1  # fail every timing guard closed, never open, on a bad timestamp


# ── Room watchers (each its own thread; long-poll loop mirrors archiver.py's run()) ──


def watch_room(
    room: str,
    base_url: str,
    wait: float,
    cursor_dir: Path,
    on_message,
    stop: threading.Event,
    label: str,
) -> None:
    cursor = base.Cursor(cursor_dir / f"{room}.cursor")
    state = cursor.read()
    first_run = state is None
    last_seq, last_generation = state if state is not None else (None, None)
    print(f"[tclk-watch] {label}: watching room={room!r}", file=sys.stderr)

    while not stop.is_set():
        if first_run:
            url = f"{base_url}/r/{room}?limit=200&format=json"
        else:
            url = f"{base_url}/r/{room}?since={last_seq}&wait={wait}&limit=200&format=json"
        try:
            view = base.fetch_json(url, timeout=wait + 15)
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            print(f"[tclk-watch] {label}: fetch failed, retrying in 5s: {exc}", file=sys.stderr)
            time.sleep(5)
            continue

        messages = view.get("messages", [])
        generation = view.get("generation")
        if last_generation is not None and generation is not None and generation != last_generation:
            print(f"[tclk-watch] {label}: ROOM RESET generation {last_generation} -> {generation}",
                  file=sys.stderr)
        last_generation = generation
        first_run = False

        for message in messages:
            on_message(message)

        if messages and "last_seq" in view:
            last_seq = view["last_seq"]
        if last_seq is not None:
            cursor.write(last_seq, last_generation)

    print(f"[tclk-watch] {label}: stopped", file=sys.stderr)


def run_deal_room(
    contract: str, offer: dict, accept: dict, accept_ts, room: str,
    args, sink: OutputSink, registry: ContractRegistry,
) -> None:
    """One thread per accepted deal. Exits (and lets the thread be reaped) once the
    contract reaches a terminal state.

    A deal room never contains its own accept (SPEC.md §2), so the room's starting state
    is reconstructed by replaying open_contract(offer) -> apply_frame(accept) here — never
    hand-set, or every later lock/reveal/refund guard would compare against a None
    contract/statement/payer/payee and reject everything.
    """
    state = tv.open_contract(offer)
    state, ok, note = tv.apply_frame(state, accept, _ms(accept_ts))
    if not ok:
        # The accept was already validated once, in run_offers_board, before this thread
        # was spawned — reaching here means those two checks disagree, which is a bug in
        # this tool, not a bad frame. Fail loud rather than watch a room with broken state.
        raise RuntimeError(f"contract {contract}: replaying its own accept failed: {note}")
    stop = threading.Event()
    lock = threading.Lock()

    def on_message(message: dict) -> None:
        nonlocal state
        with lock:
            new_state = process_message(room, message, state, sink)
            if new_state is not None:
                if new_state.status != state.status:
                    registry.update_status(contract, new_state.status)
                    if new_state.status in tv.TERMINAL_STATUSES:
                        sink.write({
                            "event": "contract_terminal", "contract": contract, "room": room,
                            "status": new_state.status, "detected_at": time.time(),
                        })
                        stop.set()
                state = new_state

    watch_room(room, args.base_url, args.wait, Path(args.cursor_dir), on_message, stop,
               label=f"deal {contract[:18]}")


def run_offers_board(
    args, sink: OutputSink, registry: ContractRegistry, spawned: dict,
    stop: threading.Event | None = None,
) -> None:
    """The persistent watcher on tclk-offers: records offers, and on a valid accept spawns
    a new deal-room thread if the contract isn't already known (covers both a fresh accept
    seen live, and — after a restart — an accept whose deal room registry entry exists but
    whose thread died with the old process).

    `stop` defaults to an Event nothing ever sets, matching real usage: the offers board is
    watched for the tool's whole life. A caller that needs a clean shutdown (tests; a future
    signal handler) passes its own Event and sets it, rather than killing the server or
    process out from under a thread that's still mid-poll.
    """
    if stop is None:
        stop = threading.Event()
    known_offers: dict[str, dict] = dict(registry.known_offers())

    def on_message(message: dict) -> None:
        text = message.get("text", "")
        if not text.startswith(tv.TCLK_PREFIX):
            return
        transport_status = base.classify(TCLK_OFFERS_ROOM, message)
        frame = tv.try_decode_frame(text)
        record = {
            "room": TCLK_OFFERS_ROOM, "seq": message.get("seq"), "from": message.get("from"),
            "_status": transport_status,
            "_tclk": {"decode_ok": frame is not None, "frame_type": frame.get("type") if frame else None},
            "_archived_at": time.time(),
        }
        sink.write(record)

        if frame is None or transport_status != "verified" or frame.get("from") != message.get("from"):
            return  # decode failure, unverified transport, or from-mismatch — see module docstring

        if frame["type"] == "offer":
            known_offers[frame["id"]] = frame
        elif frame["type"] == "accept":
            offer = known_offers.get(frame["ref"])
            if offer is None:
                return  # accept references an offer we never validated; nothing to open
            expected = tv.contract_id(offer, {k: frame.get(k) for k in
                                               ("from", "ref", "statement", "paymentKey", "nonce")
                                               if frame.get(k) is not None})
            if frame["contract"] != expected or frame["contract"] in spawned:
                return
            room = deal_room_name(frame["contract"])
            accept_ts = message.get("ts")
            registry.record_accept(frame["contract"], offer, frame, accept_ts, room)
            sink.write({"event": "contract_discovered", "contract": frame["contract"],
                        "room": room, "offer_id": offer["id"], "detected_at": time.time()})
            t = threading.Thread(
                target=run_deal_room,
                args=(frame["contract"], offer, frame, accept_ts, room, args, sink, registry),
                daemon=True, name=f"deal-{frame['contract'][:10]}",
            )
            spawned[frame["contract"]] = t
            t.start()

    watch_room(TCLK_OFFERS_ROOM, args.base_url, args.wait, Path(args.cursor_dir), on_message,
               stop, label="offers-board")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="JSONL output file, shared across all rooms")
    parser.add_argument("--cursor-dir", required=True,
                         help="directory holding one cursor file per watched room, plus the contract registry")
    parser.add_argument("--base-url", default="https://technocore.chat")
    parser.add_argument("--wait", type=float, default=10.0)
    args = parser.parse_args()

    cursor_dir = Path(args.cursor_dir)
    cursor_dir.mkdir(parents=True, exist_ok=True)
    sink = OutputSink(Path(args.out))
    registry = ContractRegistry(cursor_dir / "contracts.json")
    spawned: dict[str, threading.Thread] = {}

    # Resume every non-terminal contract from a prior run before joining the offers board,
    # so a deal doesn't sit unwatched for a whole poll cycle after a restart.
    for contract, entry in registry.pending():
        t = threading.Thread(
            target=run_deal_room,
            args=(contract, entry["offer"], entry["accept"], entry["accept_ts"], entry["room"],
                  args, sink, registry),
            daemon=True, name=f"deal-{contract[:10]}",
        )
        spawned[contract] = t
        t.start()
    if spawned:
        print(f"[tclk-watch] resumed {len(spawned)} non-terminal contract(s) from a prior run",
              file=sys.stderr)

    try:
        run_offers_board(args, sink, registry, spawned)
    except KeyboardInterrupt:
        print("\n[tclk-watch] stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
