"""Tests tclk_frame_conformance.py's per-type census against synthetic archiver.py-shaped
records: a well-formed frame counts as decode_ok, a malformed one is bucketed by its exact
rejection reason and key ordering, frame types never leak into each other's buckets, and a
non-tclk1 line is ignored entirely rather than counted as a rejection."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # tclk_frame_conformance.py, tclk_verify.py
import tclk_verify as tv  # noqa: E402
import tclk_frame_conformance as tfc  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44


def _rec(text):
    return {"text": text}


def _well_formed_offer_accept():
    now = 1_800_000_000_000
    offer = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "10",
        "asset": "FLOP", "lock": "hash", "rails": ["paper"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": "1111111111111111",
    }
    offer["id"] = tv.offer_id(offer)
    core = {"from": PAYEE_DID, "ref": offer["id"], "statement": "0x" + "11" * 32,
            "nonce": "2222222222222222"}
    accept = {"type": "accept", **core, "contract": tv.contract_id(offer, core)}
    offer_text = tv.TCLK_PREFIX + tv.canonical_json(offer)
    accept_text = tv.TCLK_PREFIX + tv.canonical_json(accept)
    return offer, accept, offer_text, accept_text


def _malformed_accept_missing_contract(offer):
    # Insertion order, no `contract` -- the exact shape flop-labs/tclk#147 reports.
    raw = {"type": "accept", "from": PAYEE_DID, "ref": offer["id"],
           "statement": "0x" + "11" * 32, "nonce": "3333333333333333"}
    return tv.TCLK_PREFIX + json.dumps(raw, separators=(",", ":"))


def test_well_formed_frames_count_as_decode_ok():
    offer, accept, offer_text, accept_text = _well_formed_offer_accept()
    result = tfc.census([_rec(offer_text), _rec(accept_text)])
    assert result["offer"]["decode_ok"] == 1
    assert result["offer"]["rejected"] == 0
    assert result["accept"]["decode_ok"] == 1
    assert result["accept"]["rejected"] == 0
    print("PASS: well-formed offer and accept frames both decode_ok with zero rejections")


def test_malformed_accept_is_bucketed_by_reason_and_key_order():
    offer, _accept, offer_text, _accept_text = _well_formed_offer_accept()
    bad_text = _malformed_accept_missing_contract(offer)
    result = tfc.census([_rec(offer_text), _rec(bad_text)])
    accept_stats = result["accept"]
    assert accept_stats["total"] == 1
    assert accept_stats["decode_ok"] == 0
    assert accept_stats["rejected"] == 1
    assert accept_stats["rejected_pct"] == 100.0
    reasons = accept_stats["reasons"]
    assert any("contract" in reason for reason in reasons), reasons
    key_orders = accept_stats["key_orders_rejected"]
    assert "type > from > ref > statement > nonce" in key_orders
    print("PASS: a malformed accept missing contract is bucketed under its exact reason "
          "and exact key ordering")


def test_frame_types_do_not_leak_into_each_others_buckets():
    offer, _accept, offer_text, _accept_text = _well_formed_offer_accept()
    bad_text = _malformed_accept_missing_contract(offer)
    result = tfc.census([_rec(offer_text), _rec(bad_text)])
    assert result["offer"]["total"] == 1
    assert result["offer"]["rejected"] == 0, "the accept-only defect must not touch offer's bucket"
    assert result["accept"]["total"] == 1
    print("PASS: a defect specific to one frame type does not appear in another type's bucket")


def test_non_tclk1_lines_are_ignored_not_counted_as_rejections():
    records = [_rec("just a plain chat message"), _rec('{"not": "tclk at all"}')]
    result = tfc.census(records)
    assert result == {}, "a non-tclk1 line must not create any frame-type bucket at all"
    print("PASS: non-tclk1 lines create no bucket and are never counted as rejections")


if __name__ == "__main__":
    test_well_formed_frames_count_as_decode_ok()
    test_malformed_accept_is_bucketed_by_reason_and_key_order()
    test_frame_types_do_not_leak_into_each_others_buckets()
    test_non_tclk1_lines_are_ignored_not_counted_as_rejections()
    print("\nALL CHECKS PASSED")
