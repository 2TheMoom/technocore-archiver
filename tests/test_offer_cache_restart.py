"""Tests OfferCache and the restart bug it exists to fix: an accept whose matching offer
was only ever seen in a PREVIOUS process lifetime must still be recognized, not silently
dropped.

Found live, not hypothesized: after several days of continuous operation across many
restarts (process crashes, an 8-hour --wait bound, a sleeping machine), a cross-reference
against independently-captured room data showed dozens of accepted contracts that
tclk_watch.py had never once logged an event for -- discovered=False, zero events -- even
though both their offer and accept frames were sitting in the room's own history the whole
time. The cause: run_offers_board's in-memory known_offers dict is rebuilt empty on every
restart, and the only durable record of an offer, ContractRegistry, doesn't get one until
AFTER its accept has already been validated -- exactly the case that doesn't exist yet
when the gap is the one being tested here.
"""

import http.server
import json
import shutil
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tclk_watch.py, tclk_verify.py
import tclk_verify as tv  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44


def make_offer_frame(now: int) -> dict:
    fields = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["memory"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": "1111111111111111",
    }
    fields["id"] = tv.offer_id(fields)
    return fields


def make_accept_frame(offer: dict) -> dict:
    core = {"from": PAYEE_DID, "ref": offer["id"], "statement": "0x" + "11" * 32,
            "nonce": "2222222222222222"}
    return {"type": "accept", **core, "contract": tv.contract_id(offer, core)}


def make_msg(seq: int, frm: str, frame: dict, ts_ms: int) -> dict:
    text = tv.TCLK_PREFIX + tv.canonical_json(frame)
    return {"seq": seq, "ts": ts_ms, "from": frm, "text": text, "nonce": seq, "sig": "TEST"}


def run_server(bodies: list[dict], call_count: list):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            n = call_count[0]
            call_count[0] = n + 1
            body = bodies[min(n, len(bodies) - 1)]
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


def _run_offers_board_once(tw, base, port, out_path, cursor_dir_path, offer_cache):
    """One simulated process lifetime: a fresh run_offers_board call (fresh in-memory
    known_offers, matching what a real restart gives it), sharing only what a restart
    would actually persist to disk -- the offer_cache and registry paths, not the process's
    own memory."""
    sink = tw.OutputSink(out_path)
    registry = tw.ContractRegistry(cursor_dir_path / "contracts.json")
    spawned: dict = {}
    stop = threading.Event()

    class Args:
        base_url = f"http://127.0.0.1:{port}"
        wait = 0.3
        out = str(out_path)
        cursor_dir = str(cursor_dir_path)

    t = threading.Thread(
        target=tw.run_offers_board, args=(Args, sink, registry, spawned, stop, offer_cache),
        daemon=True,
    )
    t.start()
    return t, stop, sink


def _read_events(out_path: Path) -> list[dict]:
    return [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]


def test_offer_cache_persists_and_reloads_across_instances():
    tmp = Path("/tmp/offer_cache_unit_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    path = tmp / "offers_cache.json"

    import tclk_watch as tw

    now = 1_800_000_000_000
    offer = make_offer_frame(now)

    cache1 = tw.OfferCache(path)
    cache1.add(offer, now_ms=now)
    assert path.exists(), "OfferCache must write to disk when given a real path"

    cache2 = tw.OfferCache(path)  # a fresh instance, as a restart would create
    assert cache2.all() == {offer["id"]: offer}
    print("PASS: an offer added by one OfferCache instance is visible to a fresh instance "
          "pointed at the same file")


def test_offer_cache_prunes_expired_offers():
    import tclk_watch as tw

    now = 1_800_000_000_000
    offer_a = make_offer_frame(now)
    offer_b = dict(make_offer_frame(now))
    offer_b["nonce"] = "9999999999999999"  # distinct id from offer_a
    offer_b["id"] = tv.offer_id({k: v for k, v in offer_b.items() if k != "id"})
    offer_b["expiresMs"] = now - 1  # already expired as of `now`

    cache = tw.OfferCache(None)  # in-memory is enough to test the pruning logic itself
    cache.add(offer_a, now_ms=now)
    cache.add(offer_b, now_ms=now)
    remaining = cache.all()
    assert offer_a["id"] in remaining
    assert offer_b["id"] not in remaining, "an offer past its own expiresMs must be pruned"
    print("PASS: adding a new offer also drops any cached offer whose expiresMs has passed")


def test_accept_recognizes_an_offer_only_seen_in_a_previous_process_lifetime():
    """The actual bug, reproduced: offer seen in 'run 1', that process stops, 'run 2'
    starts with an empty in-memory dict and only the disk-backed OfferCache in common,
    then the accept arrives. It must be discovered, not dropped."""
    import archiver as base
    import tclk_watch as tw

    original_classify = base.classify
    base.classify = lambda room, message: "verified"
    try:
        tmp = Path("/tmp/offer_cache_restart_test")
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        out_path = tmp / "out.jsonl"
        cursor_dir_path = tmp / "cursors"
        cursor_dir_path.mkdir()

        now = 1_800_000_000_000
        offer = make_offer_frame(now)
        accept = make_accept_frame(offer)

        # "Run 1": server serves only the offer, then goes quiet. The offer_cache instance
        # used here is discarded after this run, exactly as a process exiting would discard
        # its in-memory state -- only what reached disk survives.
        offer_cache_path = cursor_dir_path / "offers_cache.json"
        bodies_run1 = [
            {"messages": [make_msg(1, PAYER_DID, offer, now)], "last_seq": 1, "generation": 1},
            {"messages": [], "last_seq": 1, "generation": 1},
        ]
        call_count = [0]
        server, server_thread = run_server(bodies_run1, call_count)
        port = server.server_address[1]

        t1, stop1, _ = _run_offers_board_once(
            tw, base, port, out_path, cursor_dir_path, tw.OfferCache(offer_cache_path))
        deadline = time.time() + 10
        while call_count[0] < 2 and time.time() < deadline:
            time.sleep(0.05)
        stop1.set()
        server.shutdown()
        server_thread.join(timeout=5)
        t1.join(timeout=5)

        events_after_run1 = _read_events(out_path)
        assert not any(e.get("event") == "contract_discovered" for e in events_after_run1), (
            "the accept hasn't been sent yet -- nothing should be discovered after run 1")

        # "Run 2": brand-new process (fresh known_offers dict via a fresh run_offers_board
        # call and a fresh OfferCache instance re-reading the same path), server now serves
        # the accept.
        bodies_run2 = [{"messages": [make_msg(2, PAYEE_DID, accept, now + 60_000)],
                        "last_seq": 2, "generation": 1}]
        call_count2 = [0]
        server2, server_thread2 = run_server(bodies_run2, call_count2)
        port2 = server2.server_address[1]

        t2, stop2, _ = _run_offers_board_once(
            tw, base, port2, out_path, cursor_dir_path, tw.OfferCache(offer_cache_path))
        deadline = time.time() + 10
        contract = accept["contract"]
        discovered = False
        while time.time() < deadline:
            events = _read_events(out_path)
            if any(e.get("event") == "contract_discovered" and e.get("contract") == contract
                   for e in events):
                discovered = True
                break
            time.sleep(0.05)
        stop2.set()
        server2.shutdown()
        server_thread2.join(timeout=5)
        t2.join(timeout=5)

        final_events = _read_events(out_path)
        assert discovered, (
            "an accept whose offer was only seen in a previous process lifetime must "
            "still be discovered once the offer cache is shared across the restart",
            final_events)
        assert not any(e.get("event") == "accept_unknown_offer" for e in final_events), (
            "the offer was in fact known (via the cache) -- this must not be reported as "
            "an unknown-offer miss", final_events)
        print("PASS: an accept is correctly discovered even when its matching offer was "
              "only ever seen in a prior process lifetime, via the persisted offer cache")
    finally:
        base.classify = original_classify


def test_accept_for_a_truly_unknown_offer_is_reported_not_silently_dropped():
    """The genuine-miss case (offer cache is empty/None): must still not crash, and must
    leave a visible record rather than nothing at all."""
    import archiver as base
    import tclk_watch as tw

    original_classify = base.classify
    base.classify = lambda room, message: "verified"
    try:
        tmp = Path("/tmp/offer_cache_unknown_test")
        if tmp.exists():
            shutil.rmtree(tmp)
        tmp.mkdir(parents=True)
        out_path = tmp / "out.jsonl"
        cursor_dir_path = tmp / "cursors"
        cursor_dir_path.mkdir()

        now = 1_800_000_000_000
        offer = make_offer_frame(now)
        accept = make_accept_frame(offer)  # offer itself is never sent to this server

        bodies = [{"messages": [make_msg(1, PAYEE_DID, accept, now)], "last_seq": 1, "generation": 1}]
        call_count = [0]
        server, server_thread = run_server(bodies, call_count)
        port = server.server_address[1]

        t, stop, _ = _run_offers_board_once(tw, base, port, out_path, cursor_dir_path, tw.OfferCache(None))
        deadline = time.time() + 10
        while call_count[0] < 1 and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)  # let the single poll's on_message calls finish
        stop.set()
        server.shutdown()
        server_thread.join(timeout=5)
        t.join(timeout=5)

        events = _read_events(out_path)
        assert any(e.get("event") == "accept_unknown_offer" and e.get("ref") == offer["id"]
                   for e in events), (
            "an accept referencing a genuinely never-seen offer must be reported, not "
            "just silently returned from", events)
        print("PASS: an accept for a genuinely unknown offer is reported as such, not "
              "silently discarded")
    finally:
        base.classify = original_classify


if __name__ == "__main__":
    test_offer_cache_persists_and_reloads_across_instances()
    test_offer_cache_prunes_expired_offers()
    test_accept_recognizes_an_offer_only_seen_in_a_previous_process_lifetime()
    test_accept_for_a_truly_unknown_offer_is_reported_not_silently_dropped()
    print("\nALL CHECKS PASSED")
