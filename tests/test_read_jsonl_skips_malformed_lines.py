"""Tests _read_jsonl's tolerance for a corrupted line, in every tool that has its own copy
of this function: kibble_tclk_xref.py, kibble_verdict_census.py, tclk_frame_conformance.py,
sonnet_registration_census.py.

Found live: after a disk-full OSError and a few forced process kills during days of
continuous archiving, one line in a multi-hundred-thousand-line file came out split across
two lines -- a write interrupted mid-flush, not a bug in what wrote it. Every one of these
four analysis tools crashed on that single bad line instead of running the analysis over
everything else, which is the wrong trade for a corpus this size.
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import kibble_tclk_xref
import kibble_verdict_census
import sonnet_registration_census
import tclk_frame_conformance

MODULES = [kibble_tclk_xref, kibble_verdict_census, tclk_frame_conformance,
           sonnet_registration_census]


def _write_fixture(path: Path) -> None:
    path.write_text(
        '{"seq": 1, "text": "a"}\n'
        'this is not json\n'
        '{"seq": 2, "text": "b"}\n'
        '{"seq": 3, "tex\n'  # truncated mid-object by an interrupted write, its own line
        '{"seq": 4, "text": "d"}\n',
        encoding="utf-8",
    )


def test_every_read_jsonl_skips_malformed_lines_and_keeps_the_rest():
    tmp = Path("/tmp/read_jsonl_malformed_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    fixture = tmp / "mixed.jsonl"
    _write_fixture(fixture)

    for module in MODULES:
        records = module._read_jsonl(fixture)
        seqs = [r["seq"] for r in records]
        assert seqs == [1, 2, 4], (
            f"{module.__name__}._read_jsonl should keep the 3 valid lines in order and "
            f"skip the 2 malformed ones, got seqs={seqs}")

    print("PASS: all four tools' _read_jsonl skip malformed lines and keep every valid "
          "one, in order")


def test_a_fully_clean_file_is_unaffected():
    tmp = Path("/tmp/read_jsonl_clean_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    fixture = tmp / "clean.jsonl"
    fixture.write_text('{"seq": 1}\n{"seq": 2}\n{"seq": 3}\n', encoding="utf-8")

    for module in MODULES:
        records = module._read_jsonl(fixture)
        assert [r["seq"] for r in records] == [1, 2, 3]

    print("PASS: a file with no malformed lines behaves exactly as before")


if __name__ == "__main__":
    test_every_read_jsonl_skips_malformed_lines_and_keeps_the_rest()
    test_a_fully_clean_file_is_unaffected()
    print("\nALL CHECKS PASSED")
