"""Tests kibble_verdict_census.py's counting logic against synthetic archiver.py-shaped
records -- not against a live board, so what's under test is the census math itself:
same-job reposts collapse, cross-job reuse counts, template blanking catches
category/digit-parameterised reuse, and an unverified transport is never counted."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # kibble_verdict_census.py
import kibble_verdict_census as kvc  # noqa: E402

DID_A = "did:key:z6Mk" + "a" * 44
DID_B = "did:key:z6Mk" + "b" * 44


def _rec(seq, who, text, status="verified"):
    return {"seq": seq, "from": who, "text": text, "_status": status}


def test_same_job_repost_is_a_revision_not_reuse():
    records = [
        _rec(1, DID_A, "ATTEST v1 | k001 | useful | first pass, looks fine"),
        _rec(2, DID_A, "ATTEST v1 | k001 | useful | first pass, looks fine"),  # same job, same reason
    ]
    result = kvc.report(records)
    assert result["accepts"]["total"] == 1, "a same-job repost must collapse, not count twice"
    assert result["accepts"]["exact_reused"] == 0
    print("PASS: a same-job repost is collapsed to one verdict and never counted as reuse")


def test_reuse_across_different_jobs_is_counted():
    records = [
        _rec(1, DID_A, "ATTEST v1 | k001 | useful | reviewed and found the result informative and well-reasoned."),
        _rec(2, DID_A, "ATTEST v1 | k002 | useful | reviewed and found the result informative and well-reasoned."),
        _rec(3, DID_A, "ATTEST v1 | k003 | useful | a genuinely distinct observation about this specific deliverable"),
    ]
    result = kvc.report(records)
    c = result["accepts"]
    assert c["total"] == 3
    assert c["exact_reused"] == 2, "both copies of the repeated reason count, not just the second"
    assert abs(c["exact_reused_pct"] - (200.0 / 3)) < 1e-6
    print("PASS: a reason reused across two different jobs by the same attestor counts both instances")


def test_template_blanking_catches_category_and_digit_parameterised_reuse():
    records = [
        _rec(1, DID_A, "ATTEST v1 | k001 | useful | Verified deliverable: meets stated technical criteria for build task with rigorous domain precision."),
        _rec(2, DID_A, "ATTEST v1 | k002 | useful | Verified deliverable: meets stated technical criteria for research task with rigorous domain precision."),
    ]
    result = kvc.report(records)
    c = result["accepts"]
    assert c["exact_reused"] == 0, "the two reasons differ verbatim (build vs research)"
    assert c["template_reused"] == 2, "they are identical once the category token is blanked"
    print("PASS: reuse that only differs by the job-category word is caught by template blanking, "
          "not the exact-match check")


def test_unverified_transport_is_never_counted():
    records = [
        _rec(1, DID_A, "ATTEST v1 | k001 | useful | some reason", status="verified"),
        _rec(2, DID_A, "ATTEST v1 | k002 | useful | some reason", status="failed"),  # bad signature
        _rec(3, DID_A, "ATTEST v1 | k003 | useful | some reason", status="unsigned"),
    ]
    result = kvc.report(records)
    assert result["verified_attest_messages"] == 1, (
        "only the record whose transport signature actually verified may be counted")
    print("PASS: an ATTEST-shaped message archiver.py could not verify is excluded entirely, "
          "not counted as an unverified verdict")


def test_reject_control_is_independent_of_accept_census():
    records = [
        _rec(1, DID_B, "ATTEST v1 | k001 | not | empty placeholder"),
        _rec(2, DID_B, "ATTEST v1 | k002 | not | empty placeholder"),
        _rec(3, DID_A, "ATTEST v1 | k010 | useful | unique reason one"),
    ]
    result = kvc.report(records)
    assert result["rejects_control"]["total"] == 2
    assert result["rejects_control"]["exact_reused"] == 2
    assert result["accepts"]["total"] == 1
    assert result["accepts"]["exact_reused"] == 0
    print("PASS: accept and reject-control censuses are tallied independently of each other")


if __name__ == "__main__":
    test_same_job_repost_is_a_revision_not_reuse()
    test_reuse_across_different_jobs_is_counted()
    test_template_blanking_catches_category_and_digit_parameterised_reuse()
    test_unverified_transport_is_never_counted()
    test_reject_control_is_independent_of_accept_census()
    print("\nALL CHECKS PASSED")
