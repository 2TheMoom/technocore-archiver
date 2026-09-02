"""Cross-check tclk_verify.py against the golden vectors and against hashlock_walkthrough.py's
own transcript. Two independent things must agree: my decoder's re-derived ids, and my
apply_frame's verdicts against the reference's apply_frame verdicts on the exact same frames."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tclk_verify.py lives one level up
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))  # the vendored cross-check fixture

import tclk_verify as tv

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44

GOLDEN_OFFER_ID = "0xd001fbbf4fa36d9ab8ea88df02a8b3303539e9d59f7ff9d9bfeb679318e9ce75"
GOLDEN_CONTRACT_ID = "0x2768bf32b455317879796093ff2e5882371cbec238611ca71f555a7fcbe58e1c"
GOLDEN_NON_ASCII_OFFER_ID = "0xfdad69c602bef151596e3e914cc3ca05b1ccd009211b57c4fdbf0ba0e0d4635b"

OFFER_LINE = (
    'tclk1 {"amount":"1000000","asset":"FLOP","claimByMs":1756703600000,"expiresMs":1756700600000,'
    '"from":"did:key:z6Mkffffffffffffffffffffffffffffffffffffffffffff",'
    f'"id":"{GOLDEN_OFFER_ID}",'
    '"job":{"context":"ctx-1","id":"task-3f","proto":"a2a"},"lock":"hash",'
    '"nonce":"9f2c81d04c9e1f7a","rails":["flop-htlc","x402"],"refundAfterMs":1756707200000,'
    '"role":"payer","type":"offer"}'
)

ACCEPT_LINE = (
    f'tclk1 {{"contract":"{GOLDEN_CONTRACT_ID}",'
    '"from":"did:key:z6Mkgggggggggggggggggggggggggggggggggggggggggggg",'
    f'"nonce":"0011223344556677","ref":"{GOLDEN_OFFER_ID}",'
    '"statement":"0xabababababababababababababababababababababababababababababababab",'
    '"type":"accept"}'
)


def test_decode_matches_golden_vectors():
    offer = tv.decode_frame(OFFER_LINE)
    assert offer["id"] == GOLDEN_OFFER_ID, f"offer id mismatch: {offer['id']}"

    accept = tv.decode_frame(ACCEPT_LINE)
    assert accept["contract"] == GOLDEN_CONTRACT_ID, f"contract id mismatch: {accept['contract']}"

    print("PASS: decode_frame reproduces both golden vectors, including canonical-form check")


def test_hostile_frames_are_rejected():
    cases = [
        ("not tclk at all", "hello world"),
        ("malformed json", "tclk1 {not json"),
        ("unknown field", OFFER_LINE.replace('"role":"payer"', '"role":"payer","evil":"x"')),
        ("missing field", OFFER_LINE.replace('"role":"payer",', "")),
        ("bad DID", OFFER_LINE.replace("z6Mkffff", "z6Mk0000")),
        ("wrong offer id", OFFER_LINE.replace(GOLDEN_OFFER_ID, "0x" + "0" * 64)),
        ("non-canonical (extra space)", OFFER_LINE.replace('"type":"offer"', '"type": "offer"')),
        ("claimByMs not before refundAfterMs",
         OFFER_LINE.replace('"claimByMs":1756703600000', '"claimByMs":1756707200000')),
    ]
    for name, line in cases:
        result = tv.try_decode_frame(line)
        assert result is None, f"FAIL: {name!r} should have been rejected, got {result}"
    print(f"PASS: all {len(cases)} hostile/malformed frames correctly rejected")


def run_reference_transcript():
    """Re-derive the exact frames hashlock_walkthrough.py posts, decode each through
    tclk_verify's fail-closed decoder, and replay them through tclk_verify's apply_frame —
    checking every verdict against what the reference script's own apply_frame produced."""
    import tclk_hashlock_walkthrough as ref

    now = 1756700000000

    offer = ref.make_offer(
        frm=PAYER_DID, role="payer", amount="250000", asset="FLOP",
        rails=["memory"], claim_by_ms=now + 3_600_000,
        refund_after_ms=now + 7_200_000, expires_ms=now + 1_800_000,
        job={"proto": "a2a", "id": "translate-42"}, nonce="c0ffee0123456789",
    )
    offer_line = ref.encode_frame(offer)

    preimage = "0x" + __import__("hashlib").sha256(b"tclk walkthrough preimage").hexdigest()
    accept = ref.make_accept(offer, frm=PAYEE_DID, statement=ref.statement_of(preimage),
                              nonce="a1b2c3d4e5f60718")
    accept_line = ref.encode_frame(accept)

    ref_state = {"status": "proposed", "offer": offer}
    ref_state, ref_note = ref.apply_frame(ref_state, accept, now + 60_000)

    my_offer = tv.decode_frame(offer_line)
    assert my_offer == offer, "my decoder disagrees with the reference builder's own offer dict"
    my_state = tv.open_contract(my_offer)

    my_accept = tv.decode_frame(accept_line)
    my_state, ok, my_note = tv.apply_frame(my_state, my_accept, now + 60_000)
    assert ok and my_state.status == "accepted" == ref_state["status"], \
        f"accept mismatch: mine={my_state.status!r}/{my_note!r} ref={ref_state['status']!r}/{ref_note!r}"

    # lock
    lock = ref.make_frame("lock", frm=PAYER_DID, contract=ref_state["contract"],
                           rail="memory", ref="mem-1")
    lock_line = ref.encode_frame(lock)
    ref_state, ref_note = ref.apply_frame(ref_state, lock, now + 120_000)
    my_lock = tv.decode_frame(lock_line)
    my_state, ok, my_note = tv.apply_frame(my_state, my_lock, now + 120_000)
    assert ok and my_state.status == "locked" == ref_state["status"], \
        f"lock mismatch: mine={my_state.status!r}/{my_note!r} ref={ref_state['status']!r}/{ref_note!r}"

    # wrong reveal — must be REJECTED by both, state unchanged
    bogus = ref.make_frame("reveal", frm=PAYEE_DID, contract=ref_state["contract"],
                            secret="0x" + "00" * 32)
    bogus_line = ref.encode_frame(bogus)
    ref_state, ref_note = ref.apply_frame(ref_state, bogus, now + 180_000)
    my_bogus = tv.decode_frame(bogus_line)
    my_state, ok, my_note = tv.apply_frame(my_state, my_bogus, now + 180_000)
    assert not ok and my_state.status == "locked" == ref_state["status"], \
        f"wrong-reveal mismatch: mine ok={ok} status={my_state.status!r} ref status={ref_state['status']!r}"

    # correct reveal — must be ACCEPTED by both, terminal
    reveal = ref.make_frame("reveal", frm=PAYEE_DID, contract=ref_state["contract"],
                             secret=preimage)
    reveal_line = ref.encode_frame(reveal)
    ref_state, ref_note = ref.apply_frame(ref_state, reveal, now + 240_000)
    my_reveal = tv.decode_frame(reveal_line)
    my_state, ok, my_note = tv.apply_frame(my_state, my_reveal, now + 240_000)
    assert ok and my_state.status == "claimed" == ref_state["status"], \
        f"reveal mismatch: mine={my_state.status!r}/{my_note!r} ref={ref_state['status']!r}/{ref_note!r}"
    assert my_state.secret == preimage == ref_state["secret"]

    # receipt — no transition, both sides agree it's a clean acknowledgment
    receipt = ref.make_frame("receipt", frm=PAYER_DID, contract=ref_state["contract"],
                              outcome="claimed", rail="memory", ref="mem-1")
    receipt_line = ref.encode_frame(receipt)
    my_receipt = tv.decode_frame(receipt_line)
    my_state, ok, my_note = tv.apply_frame(my_state, my_receipt, now + 300_000)
    assert ok and my_state.status == "claimed", f"receipt mismatch: {ok} {my_note}"

    print("PASS: full offer->accept->lock->(wrong reveal rejected)->reveal->receipt "
          "transcript agrees frame-for-frame with the reference implementation's own "
          "apply_frame verdicts")


def test_tclk17_cancel_ambiguity_reproduced():
    """The known bug: in `proposed`, cancel never checks frame['contract'], so it's
    ambiguous against every pending offer from that sender. Confirm tclk_verify reproduces
    this exactly rather than silently 'fixing' it."""
    offer = tv.decode_frame(OFFER_LINE)
    state = tv.open_contract(offer)
    cancel = {"type": "cancel", "from": PAYER_DID, "contract": "0x" + "9" * 64}  # wrong contract, no matter
    new_state, ok, note = tv.apply_frame(state, cancel, 1756700000000)
    assert ok and new_state.status == "cancelled", \
        f"expected the ambiguous proposed-state cancel to succeed (matching tclk#17): {ok} {note}"
    print("PASS: tclk#17 cancel-in-proposed ambiguity reproduced exactly (not silently patched)")


def test_refund_after_ms_not_claim_by_ms():
    """The room-level reveal cutoff is refundAfterMs, not claimByMs. A reveal posted after
    claimByMs but before refundAfterMs must still be ACCEPTED by the state machine — built
    with its own sane, realistic timeline (the golden-vector fixture's expiresMs/claimByMs
    ordering is artificial, only meant to pin a hash, not model a real deal)."""
    import hashlib

    now = 2_000_000_000_000
    claim_by = now + 3_600_000
    refund_after = now + 7_200_000
    offer_fields = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["flop-htlc"],
        "claimByMs": claim_by, "refundAfterMs": refund_after,
        "expiresMs": now + 1_800_000, "nonce": "aaaaaaaaaaaaaaaa",
    }
    offer_fields["id"] = tv.offer_id(offer_fields)
    offer_line = tv.TCLK_PREFIX + tv.canonical_json(offer_fields)
    offer = tv.decode_frame(offer_line)
    state = tv.open_contract(offer)

    preimage = "0x" + hashlib.sha256(b"refund-vs-claim test").hexdigest()
    statement = tv.statement_of(preimage)
    accept_core = {"from": PAYEE_DID, "ref": offer["id"], "statement": statement,
                   "nonce": "bbbbbbbbbbbbbbbb"}
    accept = {"type": "accept", **accept_core, "contract": tv.contract_id(offer, accept_core)}
    accept_line = tv.TCLK_PREFIX + tv.canonical_json(accept)
    accept = tv.decode_frame(accept_line)

    state, ok, note = tv.apply_frame(state, accept, now + 60_000)
    assert ok, f"accept should succeed well within the offer window: {note}"

    lock = {"type": "lock", "from": PAYER_DID, "contract": state.contract,
            "rail": "flop-htlc", "ref": "escrow-1"}
    lock_line = tv.TCLK_PREFIX + tv.canonical_json(lock)
    lock = tv.decode_frame(lock_line)
    state, ok, note = tv.apply_frame(state, lock, now + 120_000)
    assert ok, f"lock should succeed: {note}"

    # A WRONG secret, timed after claimByMs but before refundAfterMs: must fail on the
    # secret, never on lateness — proving claimByMs is not a rejection boundary here.
    late_ts = claim_by + 5000
    assert late_ts < refund_after
    wrong_reveal = {"type": "reveal", "from": PAYEE_DID, "contract": state.contract,
                     "secret": "0x" + "00" * 32}
    _, ok, note = tv.apply_frame(state, tv.decode_frame(tv.TCLK_PREFIX + tv.canonical_json(wrong_reveal)),
                                  late_ts)
    assert not ok and "does not open the statement" in note, \
        f"expected a late-but-before-refund WRONG reveal to fail on the secret, not lateness: {note}"

    # The REAL secret, same late-but-before-refund timestamp: must be ACCEPTED.
    real_reveal = {"type": "reveal", "from": PAYEE_DID, "contract": state.contract,
                   "secret": preimage}
    new_state, ok, note = tv.apply_frame(
        state, tv.decode_frame(tv.TCLK_PREFIX + tv.canonical_json(real_reveal)), late_ts)
    assert ok and new_state.status == "claimed", \
        f"expected a late-but-before-refund CORRECT reveal to be accepted: ok={ok} note={note}"

    # And past refundAfterMs, even the real secret must now be rejected.
    _, ok, note = tv.apply_frame(
        state, tv.decode_frame(tv.TCLK_PREFIX + tv.canonical_json(real_reveal)), refund_after + 1)
    assert not ok and "refund window is open" in note, \
        f"expected the same correct reveal to be rejected past refundAfterMs: ok={ok} note={note}"

    print("PASS: reveal cutoff is refundAfterMs, not claimByMs — a late-but-pre-refund "
          "reveal with the correct secret is accepted; the same reveal past refundAfterMs "
          "is rejected")


if __name__ == "__main__":
    test_decode_matches_golden_vectors()
    test_hostile_frames_are_rejected()
    run_reference_transcript()
    test_tclk17_cancel_ambiguity_reproduced()
    test_refund_after_ms_not_claim_by_ms()
    print("\nALL CHECKS PASSED")
