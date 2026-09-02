"""End-to-end test of tclk_watch.py's multi-room orchestration against a mock server:
offer + accept posted to tclk-offers -> deal room correctly derived and spawned -> lock,
a wrong reveal (rejected), the real reveal (claimed) posted in the deal room -> contract
reaches a terminal state and the watcher thread exits on its own.

This is the piece tclk_verify.py's own tests don't cover: room discovery, dynamic
spawning, and the registry — not the frame/state-machine math, which is already verified
separately (test_tclk_verify.py).
"""

import hashlib
import http.server
import json
import shutil
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tclk_watch.py, tclk_verify.py, archiver.py
import tclk_verify as tv  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44

# A did:key with NO real private key behind it works fine here: tclk_watch's own
# from-matching check compares the frame's `from` field against the *transport*-verified
# `from` technocore would report — the mock server plays that role directly, so no real
# Ed25519 signature is needed to exercise the routing/state-machine wiring. Real signature
# verification itself is exactly what archiver.classify() already covers and is not
# re-tested here.


def make_offer_frame(now: int) -> dict:
    fields = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["memory"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": "1111111111111111",
    }
    fields["id"] = tv.offer_id(fields)
    return fields


def make_accept_frame(offer: dict, statement: str) -> dict:
    core = {"from": PAYEE_DID, "ref": offer["id"], "statement": statement, "nonce": "2222222222222222"}
    return {"type": "accept", **core, "contract": tv.contract_id(offer, core)}


def make_msg(seq: int, frm: str, frame: dict, ts_ms: int, status: str = "verified") -> dict:
    """A room message shaped like technocore's own JSON, pre-classified: tclk_watch calls
    archiver.classify() on this, so give it exactly what makes that return `status`."""
    text = tv.TCLK_PREFIX + tv.canonical_json(frame)
    msg = {"seq": seq, "ts": ts_ms, "from": frm, "text": text}
    if status == "unsigned":
        return msg  # no nonce -> classify() returns "unsigned"
    # "verified" needs a nonce + sig that actually checks out, which needs a real key.
    # Route around that: monkeypatch archiver.classify for this test instead of minting a
    # throwaway Ed25519 identity, since what's under test here is room routing, not
    # signature math (already covered by archiver's own test suite).
    msg["nonce"] = seq
    msg["sig"] = "TEST"
    return msg


def run_server(routes: dict[str, list[dict]], call_counts: dict, lock: threading.Lock):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            room = path.rsplit("/", 1)[-1]
            with lock:
                n = call_counts.get(room, 0)
                call_counts[room] = n + 1
            bodies = routes.get(room, [])
            body = bodies[min(n, len(bodies) - 1)] if bodies else {"messages": [], "last_seq": 0}
            payload = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_full_deal_lifecycle_across_two_rooms():
    import archiver as base  # the module under test's own dependency

    # Every message in this test is pre-classified "verified" by patching classify(), since
    # what's under test is room discovery/spawning/state-machine wiring, not signature math.
    original_classify = base.classify
    base.classify = lambda room, message: "verified"
    try:
        _run_scenario()
    finally:
        base.classify = original_classify


def _run_scenario():
    import tclk_watch as tw

    now = 1_800_000_000_000
    offer = make_offer_frame(now)
    preimage = "0x" + hashlib.sha256(b"tclk_watch integration test").hexdigest()
    statement = tv.statement_of(preimage)
    accept = make_accept_frame(offer, statement)
    contract = accept["contract"]
    deal_room = tw.deal_room_name(contract)

    offers_msgs = [
        make_msg(1, PAYER_DID, offer, now),
        make_msg(2, PAYEE_DID, accept, now + 60_000),
    ]
    lock = {"type": "lock", "from": PAYER_DID, "contract": contract, "rail": "memory", "ref": "mem-1"}
    wrong_reveal = {"type": "reveal", "from": PAYEE_DID, "contract": contract, "secret": "0x" + "00" * 32}
    real_reveal = {"type": "reveal", "from": PAYEE_DID, "contract": contract, "secret": preimage}
    deal_msgs = [
        make_msg(1, PAYER_DID, lock, now + 120_000),
        make_msg(2, PAYEE_DID, wrong_reveal, now + 180_000),
        make_msg(3, PAYEE_DID, real_reveal, now + 240_000),
    ]

    routes = {
        "tclk-offers": [{"messages": offers_msgs, "last_seq": 2, "generation": 1}],
        deal_room: [
            {"messages": deal_msgs[:1], "last_seq": 1, "generation": 1},
            {"messages": deal_msgs[1:2], "last_seq": 2, "generation": 1},
            {"messages": deal_msgs[2:3], "last_seq": 3, "generation": 1},
        ],
    }
    call_counts: dict = {}
    server, server_thread = run_server(routes, call_counts, threading.Lock())
    port = server.server_address[1]

    tmp = Path("/tmp/tclk_watch_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    out_path = tmp / "out.jsonl"
    cursor_dir_path = tmp / "cursors"
    cursor_dir_path.mkdir()

    class Args:
        base_url = f"http://127.0.0.1:{port}"
        wait = 1.0
        out = str(out_path)
        cursor_dir = str(cursor_dir_path)

    sink = tw.OutputSink(out_path)
    registry = tw.ContractRegistry(cursor_dir_path / "contracts.json")
    spawned: dict = {}

    offers_stop = threading.Event()
    offers_thread = threading.Thread(
        target=tw.run_offers_board, args=(Args, sink, registry, spawned, offers_stop), daemon=True,
    )
    offers_thread.start()

    # The deal-room thread is spawned dynamically by the offers-board thread once it sees
    # the accept — wait for that, then wait for the deal thread to reach a terminal state
    # and exit on its own (run_deal_room's stop.set() on "claimed").
    deadline = time.time() + 15
    while contract not in spawned and time.time() < deadline:
        time.sleep(0.05)
    assert contract in spawned, "deal room was never spawned from the accept frame"

    deal_thread = spawned[contract]
    deal_thread.join(timeout=15)
    assert not deal_thread.is_alive(), "deal-room watcher never reached a terminal state and exited"

    records = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    events = [r for r in records if "event" in r]
    frames = [r for r in records if "_tclk" in r]

    discovered = [e for e in events if e["event"] == "contract_discovered"]
    assert len(discovered) == 1 and discovered[0]["contract"] == contract, discovered

    terminal = [e for e in events if e["event"] == "contract_terminal"]
    assert len(terminal) == 1 and terminal[0]["status"] == "claimed", terminal

    lock_record = next(r for r in frames if r["_tclk"].get("frame_type") == "lock")
    assert lock_record["_tclk"]["state_machine_ok"] is True, lock_record

    wrong_record = next(r for r in frames
                         if r["_tclk"].get("frame_type") == "reveal" and r["seq"] == 2)
    assert wrong_record["_tclk"]["state_machine_ok"] is False, wrong_record
    assert "does not open the statement" in wrong_record["_tclk"]["state_machine"], wrong_record

    real_record = next(r for r in frames
                        if r["_tclk"].get("frame_type") == "reveal" and r["seq"] == 3)
    assert real_record["_tclk"]["state_machine_ok"] is True, real_record
    assert "claimed" in real_record["_tclk"]["state_machine"], real_record

    reg_state = json.loads((cursor_dir_path / "contracts.json").read_text(encoding="utf-8"))
    assert reg_state[contract]["status"] == "claimed", reg_state

    offers_stop.set()
    offers_thread.join(timeout=5)
    assert not offers_thread.is_alive(), "offers-board watcher did not stop cleanly"
    server.shutdown()
    server_thread.join(timeout=5)
    print("PASS: full deal lifecycle across tclk-offers + a dynamically-derived deal room, "
          "including a rejected wrong-secret reveal, the correct reveal reaching 'claimed', "
          "the contract_discovered/contract_terminal events, and the registry's final state")


if __name__ == "__main__":
    test_full_deal_lifecycle_across_two_rooms()
    print("\nALL CHECKS PASSED")
