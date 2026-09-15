"""Tests that deal_slots actually bounds how many deal rooms poll at once.

Found live: a restart resumes a watcher thread for every non-terminal contract in the
registry -- after several days of continuous operation with zero contracts reaching a
terminal state, that was thousands of threads, all issuing their first long-poll request
within the same second. The result was heavy rate-limiting across nearly every room this
tool watches, including the offers board itself -- a self-inflicted thundering herd on
every restart, not evidence that the deals themselves were stuck.
"""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tclk_watch.py, tclk_verify.py
import tclk_verify as tv  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44


def make_offer_frame(now: int, nonce: str) -> dict:
    fields = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["memory"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": nonce,
    }
    fields["id"] = tv.offer_id(fields)
    return fields


def make_accept_frame(offer: dict, nonce: str) -> dict:
    core = {"from": PAYEE_DID, "ref": offer["id"], "statement": "0x" + "11" * 32, "nonce": nonce}
    return {"type": "accept", **core, "contract": tv.contract_id(offer, core)}


def test_deal_slots_bounds_concurrently_active_watchers():
    """N deal rooms, each of which would poll forever (a mock server that never answers),
    spawned at once against a deal_slots capped at a small number. At any instant, no more
    than the cap should actually be inside watch_room (i.e., past the semaphore) -- the
    rest must be sitting blocked on acquire, not making requests."""
    import tclk_watch as tw

    N = 12
    CAP = 3
    now = 1_800_000_000_000
    active = 0
    peak_active = 0
    active_lock = threading.Lock()
    release_all = threading.Event()

    # A watch_room stand-in: incrementing/decrementing a shared counter around a blocking
    # wait plays the role of "this thread is now the one making requests", without needing
    # a real HTTP server per deal room (12 real servers would be its own source of flake).
    def fake_watch_room(room, base_url, wait, cursor_dir, on_message, stop, label=None, on_poll=None):
        nonlocal active, peak_active
        with active_lock:
            active += 1
            peak_active = max(peak_active, active)
        try:
            release_all.wait(timeout=10)
        finally:
            with active_lock:
                active -= 1

    original_watch_room = tw.watch_room
    tw.watch_room = fake_watch_room
    try:
        deal_slots = threading.BoundedSemaphore(CAP)
        threads = []
        for i in range(N):
            offer = make_offer_frame(now, f"{1000 + i:016d}")
            accept = make_accept_frame(offer, f"{2000 + i:016d}")
            contract = accept["contract"]

            class Args:
                base_url = "http://127.0.0.1:0"
                wait = 1.0
                cursor_dir = "/tmp/unused"

            import tempfile
            out_dir = Path(tempfile.mkdtemp(prefix="deal_cap_test_"))
            sink = tw.OutputSink(out_dir / "out.jsonl")
            registry = tw.ContractRegistry(out_dir / "contracts.json")
            t = threading.Thread(
                target=tw.run_deal_room,
                args=(contract, offer, accept, now, tw.deal_room_name(contract),
                      Args, sink, registry, deal_slots),
                daemon=True,
            )
            threads.append(t)

        for t in threads:
            t.start()

        deadline = time.time() + 10
        while peak_active < CAP and active < N and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.3)  # let any over-eager thread past the cap show up, if the bug regresses

        assert peak_active <= CAP, (
            f"deal_slots={CAP} but {peak_active} deal rooms were simultaneously active -- "
            "the cap did not hold")
        assert active == CAP, (
            f"expected exactly {CAP} active with {N - CAP} queued behind the semaphore, "
            f"found {active} active")

        release_all.set()
        for t in threads:
            t.join(timeout=10)

        print(f"PASS: {N} deal rooms spawned at once, deal_slots={CAP} held peak concurrent "
              f"activity to exactly {peak_active}, the rest queued rather than all polling "
              f"simultaneously")
    finally:
        tw.watch_room = original_watch_room


if __name__ == "__main__":
    test_deal_slots_bounds_concurrently_active_watchers()
    print("\nALL CHECKS PASSED")
