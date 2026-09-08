"""Tests tcr1_export.py against a terminal tclk contract state, and -- the part that
actually proves something about flop-labs/technocore-chat#281 rather than asserting it --
against the real `tc-receipts` package (wanshade/tc-receipts), not a reimplementation of
its schema.

This is the one test file in this repo with an extra dependency: `pip install tc-receipts`
(pulls in `jsonschema`; `cryptography` is already required by archiver.py). That is
deliberate rather than an oversight -- the whole point of this file is exercising the real
verifier from the other side of the interop, not a local stand-in for it. If tc-receipts
isn't installed, importing it below fails loudly rather than silently skipping, so a run
of this file never quietly reports success without having proven anything.
"""

import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tcr1_export.py, tclk_verify.py
import tclk_verify as tv  # noqa: E402
import tcr1_export as tcr1  # noqa: E402

from tc_receipts.keys import generate_key  # noqa: E402
from tc_receipts.receipt import create_receipt, verify_receipt  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44


def _claimed_hash_lock_state() -> tv.ContractState:
    """A terminal ContractState reached the same way tclk_watch.py reaches one: replaying
    real offer/accept/lock/reveal frames through tclk_verify's own state machine, not a
    hand-typed stand-in for what verification would have produced."""
    now = 1_800_000_000_000
    offer = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["paper"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": "1111111111111111",
    }
    offer["id"] = tv.offer_id(offer)
    preimage = "0x" + hashlib.sha256(b"tcr1 export test").hexdigest()
    statement = tv.statement_of(preimage)
    accept_core = {
        "from": PAYEE_DID, "ref": offer["id"], "statement": statement,
        "nonce": "2222222222222222",
    }
    contract = tv.contract_id(offer, accept_core)
    accept = {"type": "accept", **accept_core, "contract": contract}
    lock = {"type": "lock", "from": PAYER_DID, "contract": contract, "rail": "paper", "ref": contract}
    reveal = {"type": "reveal", "from": PAYEE_DID, "contract": contract, "secret": preimage}

    state = tv.open_contract(offer)
    for frame in (accept, lock, reveal):
        state, ok, note = tv.apply_frame(state, frame, now)
        assert ok, f"reference replay rejected its own {frame['type']} frame: {note}"
    assert state.status == "claimed", state.status
    return state


def test_non_terminal_state_is_refused():
    now = 1_800_000_000_000
    offer = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "500",
        "asset": "FLOP", "lock": "hash", "rails": ["paper"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": "1111111111111111",
    }
    offer["id"] = tv.offer_id(offer)
    state = tv.open_contract(offer)
    try:
        tcr1.build_deal_document(state)
        raise AssertionError("expected ExportError for a 'proposed' contract")
    except tcr1.ExportError:
        pass
    print("PASS: a non-terminal contract state is refused rather than exported early")


def test_descriptor_hash_and_size_match_the_written_bytes(tmp_path=None):
    import shutil
    import tempfile

    state = _claimed_hash_lock_state()
    paper_check = {"ref_matches_contract": True, "kv_record_found": True, "kv_terms_match": True}

    encoded, descriptor = tcr1.build_artifact(state, uri="file:deal.tcr1.json", paper_check=paper_check)
    assert descriptor["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert descriptor["size"] == len(encoded)
    assert descriptor["type"] == "technocore-tclk-deal-receipt"

    workdir = Path(tempfile.mkdtemp(prefix="tcr1_export_test_"))
    try:
        artifact_path = workdir / "deal.tcr1.json"
        written_descriptor = tcr1.write_artifact(artifact_path, state, paper_check=paper_check)
        on_disk = artifact_path.read_bytes()
        assert on_disk == encoded, "write_artifact must store exactly the canonicalized bytes"
        assert written_descriptor["sha256"] == hashlib.sha256(on_disk).hexdigest()
        assert written_descriptor["size"] == len(on_disk)

        try:
            tcr1.write_artifact(artifact_path, state, paper_check=paper_check)
            raise AssertionError("expected write_artifact to refuse to overwrite an existing file")
        except FileExistsError:
            pass
    finally:
        shutil.rmtree(workdir)
    print("PASS: the TCR-1 descriptor's sha256/size match the exact bytes written to disk, "
          "and a second write never overwrites the first")


def test_paper_rail_check_is_a_separate_labeled_field_not_the_completion_claim():
    state = _claimed_hash_lock_state()
    without_check = tcr1.build_deal_document(state)
    assert "paper_rail_check" not in without_check
    assert any("PaperRail" in d for d in without_check["disclaims"]) is False

    with_mismatch = tcr1.build_deal_document(
        state, paper_check={"ref_matches_contract": True, "kv_record_found": True, "kv_terms_match": False}
    )
    # The completion claim (contract.status == "claimed") is unaffected by a paper-rail
    # mismatch -- tclk_verify's own state machine already decided that from the room's
    # signed frames alone. The mismatch is visible, but never overwrites what the frames
    # established, matching PaperRail's "cross-check, not a gate" role in tclk_watch.py.
    assert with_mismatch["contract"]["status"] == "claimed"
    assert with_mismatch["paper_rail_check"]["kv_terms_match"] is False
    assert any("PaperRail" in d for d in with_mismatch["disclaims"])
    print("PASS: a paper-rail mismatch is reported as its own labeled field and never "
          "changes or is merged into the completion claim")


def test_interop_with_the_real_tc_receipts_package():
    """The actual proof for flop-labs/technocore-chat#281: build a real signed TCR-1
    receipt using tc-receipts' own code, referencing our exported artifact file, and
    confirm tc-receipts' own hash_file() -- not ours -- computes the identical sha256 and
    size, and that tc-receipts' own verify_receipt() accepts it."""
    import shutil
    import tempfile

    state = _claimed_hash_lock_state()
    paper_check = {"ref_matches_contract": True, "kv_record_found": True, "kv_terms_match": True}

    workdir = Path(tempfile.mkdtemp(prefix="tcr1_export_interop_"))
    try:
        artifact_path = workdir / "deal.tcr1.json"
        our_descriptor = tcr1.write_artifact(artifact_path, state, paper_check=paper_check)

        task_path = workdir / "task.json"
        task_path.write_text(
            '{"id":"flop-labs/technocore-chat#281","issuer":"flop-labs/technocore-chat"}',
            encoding="utf-8",
        )

        key = generate_key()
        receipt = create_receipt(
            task_path, [artifact_path], key, now=datetime(2026, 9, 8, tzinfo=UTC)
        )

        their_entry = receipt["artifacts"][0]
        assert their_entry["sha256"] == our_descriptor["sha256"], (
            "tc-receipts' own hash_file() must agree with our descriptor's sha256 over "
            "the exact same artifact bytes", their_entry, our_descriptor)
        assert their_entry["size"] == our_descriptor["size"]

        result = verify_receipt(receipt, artifacts=[artifact_path])
        assert result["artifacts"] == "verified", result
        assert result["cryptographic"] == "verified", result
    finally:
        shutil.rmtree(workdir)
    print("PASS: a real tc-receipts receipt referencing our exported artifact verifies "
          "end-to-end under tc-receipts' own code, with sha256/size agreeing independently")


if __name__ == "__main__":
    test_non_terminal_state_is_refused()
    test_descriptor_hash_and_size_match_the_written_bytes()
    test_paper_rail_check_is_a_separate_labeled_field_not_the_completion_claim()
    test_interop_with_the_real_tc_receipts_package()
    print("\nALL CHECKS PASSED")
