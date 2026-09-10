"""Tests kibble_tclk_xref.py's linkage logic against synthetic archiver.py/tclk_watch.py-
shaped records: a job's board verdict must not be affected by anything except its own
ATTEST records, a deal's terminal status must come only from tclk_watch.py's own
contract_terminal events (never a raw frame-type guess), and the one finding this module
exists to surface -- a 'not' verdict whose deal still claimed -- must be flagged."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # kibble_tclk_xref.py, tclk_verify.py
import tclk_verify as tv  # noqa: E402
import kibble_tclk_xref as xref  # noqa: E402

PAYER_DID = "did:key:z6Mk" + "f" * 44
PAYEE_DID = "did:key:z6Mk" + "g" * 44
ATTESTOR_A = "did:key:z6Mk" + "a" * 44
ATTESTOR_B = "did:key:z6Mk" + "b" * 44


def _kibble_rec(seq, who, text):
    return {"seq": seq, "from": who, "text": text, "_status": "verified"}


def _offer_frame(job_id, nonce="1111111111111111"):
    now = 1_800_000_000_000
    fields = {
        "type": "offer", "from": PAYER_DID, "role": "payer", "amount": "10",
        "asset": "FLOP", "lock": "hash", "rails": ["paper"],
        "claimByMs": now + 3_600_000, "refundAfterMs": now + 7_200_000,
        "expiresMs": now + 1_800_000, "nonce": nonce,
        "job": {"proto": "kibble", "id": job_id},
    }
    fields["id"] = tv.offer_id(fields)
    return fields


def _accept_frame(offer, nonce="2222222222222222"):
    core = {"from": PAYEE_DID, "ref": offer["id"], "statement": "0x" + "11" * 32, "nonce": nonce}
    return {"type": "accept", **core, "contract": tv.contract_id(offer, core)}


def _offers_rec(seq, frame):
    return {"seq": seq, "from": frame["from"],
            "text": tv.TCLK_PREFIX + tv.canonical_json(frame), "_status": "verified"}


def test_a_not_verdict_that_still_claimed_is_flagged():
    offer = _offer_frame("k-bad-job")
    accept = _accept_frame(offer)
    kibble_records = [
        _kibble_rec(1, ATTESTOR_A, "ATTEST v1 | k-bad-job | not | fails the stated success condition"),
    ]
    offers_records = [_offers_rec(1, offer), _offers_rec(2, accept)]
    watch_records = [{"event": "contract_terminal", "contract": accept["contract"], "status": "claimed"}]

    result = xref.cross_reference(kibble_records, offers_records, watch_records)
    assert result["crosstab"].get("not / claimed") == 1
    assert len(result["rejected_but_paid_examples"]) == 1
    assert result["rejected_but_paid_examples"][0]["job_id"] == "k-bad-job"
    print("PASS: a job the board rejected, whose deal still claimed, is counted and named")


def test_useful_verdict_with_no_linked_offer_is_not_double_counted_as_unpaid():
    kibble_records = [
        _kibble_rec(1, ATTESTOR_A, "ATTEST v1 | k-untracked | useful | looks fine"),
    ]
    result = xref.cross_reference(kibble_records, [], [])
    assert result["kibble_linked_offers"] == 0, (
        "a kibble job with no matching tclk offer must not appear in the crosstab at all")
    print("PASS: a kibble job with no linked tclk offer contributes nothing to the crosstab")


def test_job_with_no_board_verdict_is_none_not_absent():
    offer = _offer_frame("k-unverdicted")
    accept = _accept_frame(offer)
    offers_records = [_offers_rec(1, offer), _offers_rec(2, accept)]
    watch_records = [{"event": "contract_terminal", "contract": accept["contract"], "status": "claimed"}]

    result = xref.cross_reference([], offers_records, watch_records)
    assert result["crosstab"].get("none / claimed") == 1
    print("PASS: a tclk-funded job with zero board verdicts is counted as 'none', "
          "distinct from a job that was actually rejected")


def test_terminal_status_comes_only_from_contract_terminal_events():
    """A raw 'receipt' or 'refund' frame type must NOT be enough on its own -- only
    tclk_watch.py's own state-machine-verified contract_terminal event counts, since that
    is the whole reason this module reads tclk_watch.py's output instead of re-scanning
    frame types itself."""
    offer = _offer_frame("k-pending")
    accept = _accept_frame(offer)
    offers_records = [_offers_rec(1, offer), _offers_rec(2, accept)]

    result = xref.cross_reference([], offers_records, [])  # no contract_terminal event at all
    assert result["crosstab"].get("none / pending") == 1
    print("PASS: with no contract_terminal event, a deal is 'pending', never guessed at "
          "from frame types alone")


def test_disagreeing_attestors_are_mixed_not_useful_or_not():
    offer = _offer_frame("k-disputed")
    accept = _accept_frame(offer)
    kibble_records = [
        _kibble_rec(1, ATTESTOR_A, "ATTEST v1 | k-disputed | useful | looks complete"),
        _kibble_rec(2, ATTESTOR_B, "ATTEST v1 | k-disputed | not | actually incomplete"),
    ]
    offers_records = [_offers_rec(1, offer), _offers_rec(2, accept)]
    watch_records = [{"event": "contract_terminal", "contract": accept["contract"], "status": "refunded"}]

    result = xref.cross_reference(kibble_records, offers_records, watch_records)
    assert result["crosstab"].get("mixed / refunded") == 1
    print("PASS: attestors disagreeing on the same job reports as 'mixed', not silently "
          "picking one side")


if __name__ == "__main__":
    test_a_not_verdict_that_still_claimed_is_flagged()
    test_useful_verdict_with_no_linked_offer_is_not_double_counted_as_unpaid()
    test_job_with_no_board_verdict_is_none_not_absent()
    test_terminal_status_comes_only_from_contract_terminal_events()
    test_disagreeing_attestors_are_mixed_not_useful_or_not()
    print("\nALL CHECKS PASSED")
