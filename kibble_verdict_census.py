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
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator

ATTEST_RE = re.compile(r"^ATTEST\s+v1\s*\|\s*(\S+)\s*\|\s*(useful|not)\s*\|\s*(.*)$",
                        re.IGNORECASE | re.DOTALL)
CATEGORIES = ("build", "explain", "research", "review", "coordinate", "analyze", "design")


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

    total = exact_reused = template_reused = 0
    single_reason_attestors = single_reason_verdicts = 0
    for jobs in by_attestor.values():
        rows = list(jobs.values())
        exact_counts = collections.Counter(normalise(r["reason"]) for r in rows)
        tmpl_counts = collections.Counter(templatise(r["reason"]) for r in rows)
        total += len(rows)
        exact_reused += sum(n for n in exact_counts.values() if n >= 2)
        template_reused += sum(n for n in tmpl_counts.values() if n >= 2)
        if len(rows) >= 3 and len(exact_counts) == 1:
            single_reason_attestors += 1
            single_reason_verdicts += len(rows)

    return {
        "total": total,
        "exact_reused": exact_reused,
        "exact_reused_pct": 100.0 * exact_reused / total if total else 0.0,
        "template_reused": template_reused,
        "template_reused_pct": 100.0 * template_reused / total if total else 0.0,
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
    verdicts = list(load_verified_attests(records))
    accepts = [v for v in verdicts if v["verdict"] == "useful"]
    rejects = [v for v in verdicts if v["verdict"] == "not"]
    seqs = [v["seq"] for v in verdicts if v["seq"] is not None]
    return {
        "verified_attest_messages": len(verdicts),
        "distinct_attestors": len({v["who"] for v in verdicts}),
        "seq_span": [min(seqs), max(seqs)] if seqs else None,
        "accepts": census(accepts),
        "rejects_control": census(rejects),
    }


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archiver_output", help="archiver.py's --out JSONL file for the room")
    args = parser.parse_args()

    result = report(_read_jsonl(Path(args.archiver_output)))
    print(f"verified ATTEST messages : {result['verified_attest_messages']}")
    print(f"distinct attestors       : {result['distinct_attestors']}")
    if result["seq_span"]:
        print(f"seq span                 : {result['seq_span'][0]} - {result['seq_span'][1]}")
    for label, key in (("ACCEPT (useful)", "accepts"), ("REJECT (not) -- control", "rejects_control")):
        c = result[key]
        print(f"\n== {label} ==")
        print(f"   verdicts (one per attestor-job)       : {c['total']}")
        print(f"   reason reused verbatim on another job : {c['exact_reused']}  ({c['exact_reused_pct']:.1f}%)")
        print(f"   reused after blanking category/digits : {c['template_reused']}  ({c['template_reused_pct']:.1f}%)")
        print(f"   identities whose accepts are 100% one reason (n>=3)  : {c['single_reason_attestors']}"
              f"  ({c['single_reason_verdicts']} verdict(s) from them)")


if __name__ == "__main__":
    main()
