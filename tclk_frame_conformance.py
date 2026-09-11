"""Reports, per tclk/1 frame type, how many frames in an archiver.py capture of a tclk
room decode cleanly against tclk_verify.py's own fail-closed decoder -- and for the ones
that don't, why, and what key ordering they arrived in.

Origin: flop-labs/tclk#147 reports ~69% of live `accept` frames on technocore.chat as
malformed in one identical shape (missing the required `contract` field, keys in
insertion rather than sorted order) -- hand-built JSON that skips `makeAccept()` rather
than an independent implementation bug, since the shape recurs byte-for-byte across
unrelated DIDs. This module runs the same question generally, over any frame type and any
archiver.py capture, rather than one written just for `accept`: the decoder and the
question ("how much live traffic actually conforms, and does non-conformance cluster into
a few shapes or scatter randomly") apply the same way to every frame type tclk_verify.py
already decodes.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Iterable

import tclk_verify as tv


def census(records: Iterable[dict]) -> dict:
    by_type: dict[str, dict] = collections.defaultdict(lambda: {
        "total": 0, "decode_ok": 0,
        "reasons": collections.Counter(),
        "key_orders_rejected": collections.Counter(),
    })

    for record in records:
        text = (record.get("text") or "").strip()
        if not text.startswith(tv.TCLK_PREFIX):
            continue
        try:
            raw = json.loads(text[len(tv.TCLK_PREFIX):])
        except ValueError:
            continue
        if not isinstance(raw, dict):
            continue
        frame_type = raw.get("type")
        if not isinstance(frame_type, str):
            continue

        bucket = by_type[frame_type]
        bucket["total"] += 1
        try:
            tv.decode_frame(text)
            bucket["decode_ok"] += 1
        except tv.TclkDecodeError as exc:
            bucket["reasons"][str(exc)] += 1
            bucket["key_orders_rejected"][tuple(raw.keys())] += 1

    result = {}
    for frame_type, bucket in by_type.items():
        total = bucket["total"]
        ok = bucket["decode_ok"]
        result[frame_type] = {
            "total": total,
            "decode_ok": ok,
            "decode_ok_pct": round(100.0 * ok / total, 1) if total else 0.0,
            "rejected": total - ok,
            "rejected_pct": round(100.0 * (total - ok) / total, 1) if total else 0.0,
            "reasons": dict(bucket["reasons"].most_common()),
            "key_orders_rejected": {" > ".join(k): n for k, n in
                                     bucket["key_orders_rejected"].most_common()},
        }
    return result


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("archiver_output", help="archiver.py --room <tclk-offers|a deal room> output")
    args = parser.parse_args()

    result = census(_read_jsonl(Path(args.archiver_output)))
    for frame_type, stats in sorted(result.items(), key=lambda kv: -kv[1]["total"]):
        print(f"\n== {frame_type} ==")
        print(f"   total       : {stats['total']}")
        print(f"   decode_ok   : {stats['decode_ok']}  ({stats['decode_ok_pct']}%)")
        print(f"   rejected    : {stats['rejected']}  ({stats['rejected_pct']}%)")
        if stats["reasons"]:
            print("   rejection reasons:")
            for reason, n in stats["reasons"].items():
                print(f"      {n:6d}  {reason}")
            print("   key orderings among rejected:")
            for order, n in stats["key_orders_rejected"].items():
                print(f"      {n:6d}  {order}")


if __name__ == "__main__":
    main()
