"""Exports a completed tclk/1 deal's independently-verified terminal state as a TCR-1
artifact descriptor (docs/TCR-1.md, wanshade/tc-receipts) -- {type, uri, sha256, size},
meant to be referenced from someone else's `artifacts[]` array in a signed task receipt.

This is not a tclk/1 or PaperRail claim of its own. PaperRail's own module docstring says
a matching record is "evidence of a rehearsal, never of a payment," and that boundary
carries through here unchanged: the artifact proves a signed multi-frame protocol run
reached a terminal state that tclk_verify.py independently replayed and checked -- not
that value moved on any settlement rail.

Kept standalone and opt-in: nothing in tclk_watch.py's own loop depends on this module,
and it never claims TCR-1 compatibility beyond what tests/test_tcr1_export.py actually
proves against the real tc-receipts package -- see that test's docstring.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from tclk_verify import ContractState

ARTIFACT_TYPE = "technocore-tclk-deal-receipt"
ARTIFACT_VERSION = 1
CLAIM_SCOPE = "verified-tclk-protocol-completion"
TERMINAL_STATUSES = ("claimed", "refunded", "cancelled")

DISCLAIMS = (
    "payment or fund movement on any settlement rail",
    "task acceptance, authorship, or contribution truth",
    "reward, airdrop, or eligibility",
)
PAPER_RAIL_DISCLAIM = (
    "PaperRail settles nothing -- a match is evidence of a rehearsal, never of a payment"
)


class ExportError(ValueError):
    """The supplied state isn't a terminal, exportable tclk contract."""


def canonicalize(value: Any) -> bytes:
    """Restricted canonical JSON matching tc-receipts' own profile (docs/TCR-1.md): sorted
    keys, compact separators, UTF-8, unescaped Unicode, no floats. Deliberately NOT
    tclk_verify.canonical_json's ASCII-escaped frames.ts convention -- this document is a
    TCR-1 artifact, not a tclk frame, and has to canonicalize the way TCR-1 does."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def build_deal_document(state: ContractState, paper_check: dict | None = None) -> dict:
    """The artifact body for a terminal contract. `paper_check` is the deal's last
    paper_rail_check event (tclk_watch.py's own event shape) -- pass it only when the
    deal's rail is "paper". It is reported as its own separately-labeled field, never
    merged into the completion claim, so nothing here can be misread as PaperRail settling
    anything."""
    if state.status not in TERMINAL_STATUSES:
        raise ExportError(f"contract is not in a terminal state: {state.status!r}")
    if state.contract is None:
        raise ExportError("contract id is not yet known")

    contract: dict[str, Any] = {
        "id": state.contract,
        "status": state.status,
        "lock_kind": state.lock_kind,
        "rail": state.rail,
    }
    for field, value in (
        ("payer_did", state.payer_did),
        ("payee_did", state.payee_did),
        ("statement", state.statement),
        ("secret", state.secret),
    ):
        if value is not None:
            contract[field] = value

    document: dict[str, Any] = {
        "type": ARTIFACT_TYPE,
        "version": ARTIFACT_VERSION,
        "claim_scope": CLAIM_SCOPE,
        "contract": contract,
        "disclaims": list(DISCLAIMS),
    }

    if state.rail == "paper" and paper_check is not None:
        document["paper_rail_check"] = {
            "ref_matches_contract": paper_check.get("ref_matches_contract"),
            "kv_record_found": paper_check.get("kv_record_found"),
            "kv_terms_match": paper_check.get("kv_terms_match"),
        }
        document["disclaims"].append(PAPER_RAIL_DISCLAIM)

    return document


def build_artifact(
    state: ContractState, uri: str, paper_check: dict | None = None
) -> tuple[bytes, dict]:
    """Returns (encoded document bytes, TCR-1 artifact descriptor). The descriptor's
    sha256/size are computed over exactly the bytes returned -- the raw-bytes-canonicalism
    discipline 0xsheva's technocore-keyhole asked this thread to hold (flop-labs/
    technocore-chat#281): the artifact is the bytes actually stored, never a
    re-serialization a second verifier might disagree with by accident."""
    document = build_deal_document(state, paper_check)
    encoded = canonicalize(document)
    descriptor = {
        "type": ARTIFACT_TYPE,
        "uri": uri,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size": len(encoded),
    }
    return encoded, descriptor


def write_artifact(path: str | Path, state: ContractState, paper_check: dict | None = None) -> dict:
    """Exclusively creates `path` and returns its TCR-1 descriptor -- never overwrites
    existing evidence, the same convention technocore-receipt-verifier's own exporter uses
    for this thread."""
    target = Path(path)
    encoded, descriptor = build_artifact(state, f"file:{target.name}", paper_check)
    with target.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return descriptor
