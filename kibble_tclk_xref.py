"""Cross-references a kibble job's board verdict against the real-money terminal state of
the tclk/1 deal that funded it -- the real-money extension of kibble_verdict_census.py.

Origin: flop-labs/yellowpaper#3's constant-reason-rubber-stamping challenge grew a further
finding in the same thread -- linking kibble jobs to the tclk deals that pay for them turns
up cases where a `not` board verdict didn't stop a deal from settling, and a majority of
funded jobs carry no board verdict at all. That measurement scanned raw frame JSON for a
`receipt`/`refund` type tag. This module reuses two tools this repo already tests
independently instead: `tclk_watch.py`'s own state-machine-replayed `contract_terminal`
events for the terminal status (catching a malformed or out-of-turn frame a type-tag scan
would not), and `kibble_verdict_census.py`'s Ed25519-verified `ATTEST` loader for the board
verdict.

Why three input files, not one: an offer's `job` field -- the only link back to a kibble
job id -- lives on the `tclk-offers` board, but `tclk_watch.py`'s own offers-board record is
deliberately lean (decode-ok / frame-type only, no frame body) because that's all its own
live routing needs. `archiver.py` keeps the full record, `text` included, so this module
reads the offers board from an `archiver.py` capture and the deal-room terminal states from
a `tclk_watch.py` capture of the same period, rather than asking either tool to do the
other's job.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Iterable

import tclk_verify as tv
from kibble_verdict_census import load_verified_attests

TERMINAL_STATUSES = tv.TERMINAL_STATUSES  # {"claimed", "refunded", "cancelled"}


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def board_verdict_of(job_id: str, job_verdicts: dict[str, set[str]]) -> str:
    """"useful"/"not" if every counted verdict for this job agrees, "mixed" if attestors
    disagreed, "none" if the job never got a verdict at all."""
    verdicts = job_verdicts.get(job_id)
    if not verdicts:
        return "none"
    if verdicts == {"useful"}:
        return "useful"
    if verdicts == {"not"}:
        return "not"
    return "mixed"


def load_offers_and_accepts(archiver_records: Iterable[dict]) -> tuple[dict, dict]:
    """From an archiver.py capture of `tclk-offers`: offer_id -> job info (only for
    `job.proto == "kibble"` offers), and contract -> offer_id from matching accepts.
    Only transport-verified, frame-decodable, from-matching records are trusted, the same
    entry gate tclk_watch.py itself uses."""
    kibble_offers: dict[str, dict] = {}
    accept_contract_to_offer: dict[str, str] = {}
    for record in archiver_records:
        if record.get("_status") != "verified":
            continue
        text = record.get("text") or ""
        frame = tv.try_decode_frame(text)
        if frame is None or frame.get("from") != record.get("from"):
            continue
        if frame["type"] == "offer":
            job = frame.get("job")
            if isinstance(job, dict) and job.get("proto") == "kibble" and job.get("id"):
                kibble_offers[frame["id"]] = {"job_id": job["id"], "offer_id": frame["id"],
                                               "rails": frame.get("rails", [])}
        elif frame["type"] == "accept":
            accept_contract_to_offer[frame["contract"]] = frame["ref"]
    return kibble_offers, accept_contract_to_offer


def load_terminal_states(tclk_watch_records: Iterable[dict]) -> dict[str, str]:
    """contract -> terminal status, from tclk_watch.py's own state-machine-replayed
    `contract_terminal` events -- not a raw scan for a receipt/refund frame type. A
    contract that reached more than one terminal event (should not happen; tclk_watch.py's
    own watcher exits a deal room once terminal) keeps its last-seen status."""
    terminal: dict[str, str] = {}
    for record in tclk_watch_records:
        if record.get("event") == "contract_terminal":
            contract = record.get("contract")
            status = record.get("status")
            if contract and status in TERMINAL_STATUSES:
                terminal[contract] = status
    return terminal


def cross_reference(kibble_records: Iterable[dict], archiver_tclk_offers_records: Iterable[dict],
                     tclk_watch_records: Iterable[dict]) -> dict:
    verdicts = list(load_verified_attests(kibble_records))
    job_verdicts: dict[str, set[str]] = collections.defaultdict(set)
    for v in verdicts:
        job_verdicts[v["job"]].add(v["verdict"])

    kibble_offers, accept_contract_to_offer = load_offers_and_accepts(archiver_tclk_offers_records)
    terminal = load_terminal_states(tclk_watch_records)

    offer_to_contracts: dict[str, list[str]] = collections.defaultdict(list)
    for contract, offer_id in accept_contract_to_offer.items():
        offer_to_contracts[offer_id].append(contract)

    crosstab: collections.Counter = collections.Counter()
    linked = 0
    useful_but_unsettled: list[dict] = []
    for offer_id, info in kibble_offers.items():
        job_id = info["job_id"]
        verdict = board_verdict_of(job_id, job_verdicts)
        contracts = offer_to_contracts.get(offer_id, [])
        if not contracts:
            term = "not-accepted"
        else:
            statuses = {terminal[c] for c in contracts if c in terminal}
            if not statuses:
                term = "pending"
            elif "claimed" in statuses:
                term = "claimed"
            elif "refunded" in statuses:
                term = "refunded"
            else:
                term = "cancelled"
        crosstab[(verdict, term)] += 1
        linked += 1
        if verdict == "not" and term == "claimed":
            useful_but_unsettled.append({"job_id": job_id, "offer_id": offer_id,
                                          "verdict": verdict, "terminal": term})

    return {
        "kibble_linked_offers": linked,
        "crosstab": {f"{v} / {t}": n for (v, t), n in sorted(crosstab.items())},
        "rejected_but_paid_examples": useful_but_unsettled[:25],
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kibble_archive", help="archiver.py --room kibble output")
    parser.add_argument("tclk_offers_archive", help="archiver.py --room tclk-offers output")
    parser.add_argument("tclk_watch_archive", help="tclk_watch.py --out output")
    args = parser.parse_args()

    result = cross_reference(
        _read_jsonl(Path(args.kibble_archive)),
        _read_jsonl(Path(args.tclk_offers_archive)),
        _read_jsonl(Path(args.tclk_watch_archive)),
    )
    print(f"kibble jobs linked to a tclk offer : {result['kibble_linked_offers']}")
    print("\nboard verdict / deal terminal state:")
    for label, n in result["crosstab"].items():
        print(f"   {label:28s} {n}")
    if result["rejected_but_paid_examples"]:
        print(f"\n'not' verdict but the deal still claimed ({len(result['rejected_but_paid_examples'])}):")
        for ex in result["rejected_but_paid_examples"]:
            print(f"   job={ex['job_id']}  offer={ex['offer_id']}")


if __name__ == "__main__":
    main()
