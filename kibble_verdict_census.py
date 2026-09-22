"""Measures constant-verdict rubber-stamping on an ATTEST-shaped attestation board, from
archiver.py's own output -- never from the board's own API.

Origin: flop-labs/yellowpaper#3 challenges R3.5d's checker-lane bound with a measurement
against `flop-kibble`'s live board -- 40.0% of accept verdicts reuse the same free-text
reason verbatim across different jobs from the same attestor, which is a strict lower
bound on verdicts that carry zero information about the deliverable they claim to assess
(a reason can be unique and still uninformative; it cannot be reused across different work
and still be about that work). That measurement was taken through flop-kibble's own
`/api/tape`, and trusted its `did`/`from` field without checking a signature.

This module runs the same test, independently defined from the plain-English description
in the issue rather than ported from its reference tool, against `archiver.py`'s own
output for the `kibble` room -- so every verdict counted here has already had its Ed25519
signature checked against `kibble|<nonce>|<text>` by code this repo already tests against
golden vectors, not re-verified ad hoc for this one board.

The room's retention window is short relative to the volume this claim needs: a single
snapshot of `/r/kibble/export` covers on the order of tens of minutes and a few hundred
ATTEST messages, far short of a corpus built by archiving continuously over a longer
span. `archiver.py` exists exactly to accumulate past a retention window it would
otherwise lose messages to -- point it at `kibble` for as long as a comparison needs, then
run this module over its output.

A second, independent census lives here too: whether a verdict's reason was CONSTRUCTED
from the deliverable's own text, rather than reused across jobs. flop-labs/yellowpaper#3
saw its own reuse test only catches a reason repeated verbatim; a reason built as a fixed
template wrapped around a slice of the deliverable (`f"...: {deliverable[:160]}..."`) is
unique on every job, so it passes a reuse census untouched while still asserting nothing
that was actually read. This is not hypothetical -- a participant on the same board
disclosed exactly this pattern, deployed and since disabled, as a comment on that issue.
See `echoed_from_deliverable` below for the detection and its own limits.
"""

from __future__ import annotations

import argparse
import collections
import difflib
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator

ATTEST_RE = re.compile(r"^ATTEST\s+v1\s*\|\s*(\S+)\s*\|\s*(useful|not)\s*\|\s*(.*)$",
                        re.IGNORECASE | re.DOTALL)
DELIVERABLE_RE = re.compile(r"^(?:DELIVER|RESULT)\s+v1\s*\|\s*(\S+)\s*\|\s*(.*)$",
                             re.IGNORECASE | re.DOTALL)
CATEGORIES = ("build", "explain", "research", "review", "coordinate", "analyze", "design")
MIN_ECHO_LEN = 40


def parse_attest(text: str) -> tuple[str, str, str] | None:
    """-> (job_id, verdict, reason), or None if `text` isn't an ATTEST v1 line."""
    m = ATTEST_RE.match((text or "").strip())
    if not m:
        return None
    job_id, verdict, reason = m.group(1), m.group(2).lower(), m.group(3).strip()
    return job_id, verdict, reason


def normalise(reason: str) -> str:
    return re.sub(r"\s+", " ", reason.strip().lower())


def templatise(reason: str) -> str:
    """A reason parameterised only by job category or a number still says nothing about
    the deliverable, so this counts as reused too, reported alongside the exact figure."""
    s = normalise(reason)
    for c in CATEGORIES:
        s = re.sub(rf"\b{c}\b", "<category>", s)
    return re.sub(r"\d+", "<n>", s)


def parse_deliverable(text: str) -> tuple[str, str] | None:
    """-> (job_id, body), or None if `text` isn't a DELIVER/RESULT v1 line. Both carry the
    same `type v1 | job_id | body` shape ATTEST does; either can hold the payload a later
    ATTEST's reason might echo, so both feed the same job_id -> text map."""
    m = DELIVERABLE_RE.match((text or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2).strip()


def load_verified_deliverables(records: Iterable[dict]) -> dict[str, str]:
    """job_id -> every verified DELIVER/RESULT body seen for that job, concatenated. A job
    can carry more than one (an announcement plus a separate payload, or a revision);
    concatenating means a reason echoing ANY of them is still caught, not only the last."""
    bodies: dict[str, list[str]] = collections.defaultdict(list)
    for record in records:
        if record.get("_status") != "verified":
            continue
        parsed = parse_deliverable(record.get("text") or "")
        if parsed is None:
            continue
        job_id, body = parsed
        if body:
            bodies[job_id].append(body)
    return {job_id: " ".join(parts) for job_id, parts in bodies.items()}


def echoed_from_deliverable(reason: str, deliverable: str, min_len: int = MIN_ECHO_LEN) -> bool:
    """True iff a contiguous run of at least `min_len` characters of `reason` appears
    verbatim in `deliverable` -- the signature of a reason CONSTRUCTED from the deliverable
    text itself (e.g. a fixed prefix wrapped around `deliverable[:160]`), not an
    independent judgement of it. A threshold this long makes a coincidentally shared
    phrase implausible; genuine commentary about a deliverable does not reproduce 40+ of
    its own characters verbatim by chance.

    A strict LOWER bound on this pattern, same discipline as the reuse census: a shorter
    echo, a paraphrase, or a template built from a field other than the deliverable body
    all evade this check too. It catches the disclosed mechanism specifically, not every
    mechanism that could exist.
    """
    if not reason or not deliverable:
        return False
    r = normalise(reason)
    d = normalise(deliverable)
    if len(r) < min_len or len(d) < min_len:
        return False
    match = difflib.SequenceMatcher(None, r, d, autojunk=False).find_longest_match(
        0, len(r), 0, len(d))
    return match.size >= min_len


def load_verified_attests(records: Iterable[dict]) -> Iterator[dict]:
    """Yields one dict per ATTEST v1 message whose transport signature archiver.py already
    verified (`_status == "verified"`). Anything archiver.py could not verify -- failed,
    sig-missing, unsigned, malformed -- is excluded, not counted as a verdict of any kind:
    an unverified claim of who posted a verdict is not evidence about that verdict."""
    for record in records:
        if record.get("_status") != "verified":
            continue
        parsed = parse_attest(record.get("text") or "")
        if parsed is None:
            continue
        job_id, verdict, reason = parsed
        who = record.get("from")
        if not who or not reason:
            continue
        yield {"seq": record.get("seq"), "who": who, "job": job_id,
               "verdict": verdict, "reason": reason}


def census(verdicts: list[dict]) -> dict:
    """One verdict per (attestor, job) -- a same-job repost is a revision, not a second
    opinion, so it is collapsed before counting reuse across DIFFERENT jobs."""
    by_attestor: dict[str, dict[str, dict]] = collections.defaultdict(dict)
    for v in verdicts:
        by_attestor[v["who"]].setdefault(v["job"], v)

    total = exact_reused = template_reused = echoed = 0
    single_reason_attestors = single_reason_verdicts = 0
    same_job_echo_jobs: set[str] = set()
    for jobs in by_attestor.values():
        rows = list(jobs.values())
        exact_counts = collections.Counter(normalise(r["reason"]) for r in rows)
        tmpl_counts = collections.Counter(templatise(r["reason"]) for r in rows)
        total += len(rows)
        exact_reused += sum(n for n in exact_counts.values() if n >= 2)
        template_reused += sum(n for n in tmpl_counts.values() if n >= 2)
        echoed += sum(1 for r in rows if r.get("echoed_from_deliverable"))
        if len(rows) >= 3 and len(exact_counts) == 1:
            single_reason_attestors += 1
            single_reason_verdicts += len(rows)

    # Same-job cross-DID collision, independent of the per-attestor loop above (which
    # collapses to one verdict per (attestor, job) and so can never see two DIFFERENT
    # attestors on the same job): the sharper signal from the same issue -- distinct
    # identities posting byte-identical reason text on the same job. A lone attestor
    # reusing its own reason explains the first pattern; it does not explain this one.
    by_job: dict[str, dict[str, set[str]]] = collections.defaultdict(lambda: collections.defaultdict(set))
    for v in verdicts:
        by_job[v["job"]][normalise(v["reason"])].add(v["who"])
    for job_id, reasons in by_job.items():
        if any(len(dids) >= 2 for dids in reasons.values()):
            same_job_echo_jobs.add(job_id)

    return {
        "total": total,
        "exact_reused": exact_reused,
        "exact_reused_pct": 100.0 * exact_reused / total if total else 0.0,
        "template_reused": template_reused,
        "template_reused_pct": 100.0 * template_reused / total if total else 0.0,
        "echoed_from_deliverable": echoed,
        "echoed_from_deliverable_pct": 100.0 * echoed / total if total else 0.0,
        "same_job_cross_did_identical_reason_jobs": len(same_job_echo_jobs),
        # Two different counts on purpose, easy to conflate: how many DISTINCT identities
        # have posted >=3 accepts that are all one verbatim reason, versus how many total
        # verdicts those few identities are responsible for. A "7" that is actually one
        # identity posting seven times reads very differently from seven identities doing
        # it once each -- report both rather than let a caller's label pick one silently.
        "single_reason_attestors": single_reason_attestors,
        "single_reason_verdicts": single_reason_verdicts,
        "distinct_attestors": len(by_attestor),
    }


def report(records: Iterable[dict]) -> dict:
    records = list(records)  # read twice below: once for ATTEST, once for DELIVER/RESULT
    verdicts = list(load_verified_attests(records))
    deliverables = load_verified_deliverables(records)
    for v in verdicts:
        v["echoed_from_deliverable"] = echoed_from_deliverable(
            v["reason"], deliverables.get(v["job"], ""))

    accepts = [v for v in verdicts if v["verdict"] == "useful"]
    rejects = [v for v in verdicts if v["verdict"] == "not"]
    seqs = [v["seq"] for v in verdicts if v["seq"] is not None]
    return {
        "verified_attest_messages": len(verdicts),
        "distinct_attestors": len({v["who"] for v in verdicts}),
        "jobs_with_a_deliverable": len(deliverables),
        "seq_span": [min(seqs), max(seqs)] if seqs else None,
        "accepts": census(accepts),
        "rejects_control": census(rejects),
    }


def _read_jsonl(path: Path) -> list[dict]:
    """Skips, rather than crashes on, a line that isn't valid JSON. Seen live: a forced
    process kill (a crash, a disk-full OSError, this machine sleeping mid-write) can leave
    exactly one line truncated mid-write, splitting what should be one JSON object across
    two lines -- a handful of unrecoverable fragments out of hundreds of thousands of
    otherwise-intact lines, not a reason to lose the whole file's analysis."""
    records = []
    skipped = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    if skipped:
        print(f"warning: skipped {skipped} malformed line(s) in {path} "
              "(likely a write interrupted mid-line)", file=sys.stderr)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archiver_output", help="archiver.py's --out JSONL file for the room")
    args = parser.parse_args()

    result = report(_read_jsonl(Path(args.archiver_output)))
    print(f"verified ATTEST messages : {result['verified_attest_messages']}")
    print(f"distinct attestors       : {result['distinct_attestors']}")
    print(f"jobs with a deliverable  : {result['jobs_with_a_deliverable']}")
    if result["seq_span"]:
        print(f"seq span                 : {result['seq_span'][0]} - {result['seq_span'][1]}")
    for label, key in (("ACCEPT (useful)", "accepts"), ("REJECT (not) -- control", "rejects_control")):
        c = result[key]
        print(f"\n== {label} ==")
        print(f"   verdicts (one per attestor-job)       : {c['total']}")
        print(f"   reason reused verbatim on another job : {c['exact_reused']}  ({c['exact_reused_pct']:.1f}%)")
        print(f"   reused after blanking category/digits : {c['template_reused']}  ({c['template_reused_pct']:.1f}%)")
        print(f"   reason echoes >={MIN_ECHO_LEN} chars of its own deliverable : {c['echoed_from_deliverable']}"
              f"  ({c['echoed_from_deliverable_pct']:.1f}%)")
        print(f"   jobs with 2+ distinct DIDs posting the identical reason : "
              f"{c['same_job_cross_did_identical_reason_jobs']}")
        print(f"   identities whose accepts are 100% one reason (n>=3)  : {c['single_reason_attestors']}"
              f"  ({c['single_reason_verdicts']} verdict(s) from them)")


if __name__ == "__main__":
    main()
