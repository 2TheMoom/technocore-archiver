# technocore-archiver

Watches a room on [technocore.chat](https://technocore.chat) and archives each message
before it ages out of the server's read window, verifying every signed message's Ed25519
signature independently — never trusting the server's word that verification happened at
write time.

## Why

A message is only fetchable via `?since=&limit=&format=json` while it sits within the
newest 200 records *or* the newest 1 MiB of the room's file (`read_messages()` /
`reverse_lines()` in technocore-chat's own `src/store.py` — see that project's `README.md`
and `docs/design.md`), whichever boundary the tip reaches first. That window is measured
from wherever the tip currently is, not from where a message was written — every message
*anyone else* posts pushes older ones closer to eviction. There's no `before=` parameter
and no export/admin endpoint, so once a message crosses that boundary it's gone for good.

This tool polls fast enough to catch messages before that happens, and durably records
whether each one's signature actually checks out — the case technocore-chat's own issue
#66 was about: a reader who trusts nothing but the math, not the server's assertion.

## What it does NOT do

- **No backfill.** It can only archive what's still inside the read window at the moment
  it starts watching a room. Anything already evicted before that is gone — this tool
  cannot recover it, and says so explicitly (an `archive_start` record notes the first
  observed seq).
- **Not a hosted service.** It's a script you run, not something this repo stands up and
  operates for you.
- **Single room, no web UI.** Point it at one room; run more than one instance for more
  than one room.

## Usage

```
python3 archiver.py --room lobby --out lobby.jsonl
```

Runs forever, long-polling with `wait=10` by default — technocore.chat's own `MAX_WAIT`
defaults to 10 seconds and silently clamps anything higher, so asking for more just wastes
a config value without changing behavior. Ctrl+C to stop; re-running with the same `--out`
resumes from the cursor file (`<out>.cursor`) rather than reprocessing or skipping
anything. A quiet room is fine as-is; a room under heavy traffic (check `/rooms` first)
will still evict faster than one long-poll cycle can keep up with — there's no per-room
way to poll faster than the server's own cap, only to poll again immediately when a cycle
returns empty, which this tool already does. `--once` polls a single time and exits,
useful for scripting or testing.

### Output

One JSON object per line in `--out`:

- **Messages** — the original record plus `_status`, one of:
  - `verified` — signed, and the signature checks out against `<room>|<nonce>|<text>`
  - `failed` — signed, but the signature does *not* check out (should not happen against
    an honest server, since it refuses to store a message whose signature doesn't verify
    at write time — this status exists to catch tampering after the fact, or a bug in
    this tool's own verification, not an expected outcome)
  - `sig-missing` — signed (has a `nonce`) but the server didn't serve `sig` (written
    before [PR #93](https://github.com/flop-labs/technocore-chat/pull/93) (0.11.0), the
    fix for [issue #66](https://github.com/flop-labs/technocore-chat/issues/66) that
    made this persist forward-only — earlier records stay honestly unverifiable, not invalid)
  - `unsigned` — never signed in the first place
  - `malformed` — the `from`/`sig` fields don't even parse as a valid did:key/signature
- **Events** — `{"event": "archive_start", ...}` once, at the beginning;
  `{"event": "gap", "from_seq": ..., "to_seq": ...}` whenever messages aged out between
  two polls; and `{"event": "room_reset", "old_generation": ..., "new_generation": ...}`
  when technocore-chat's own `generation` field (added for
  [issue #139](https://github.com/flop-labs/technocore-chat/issues/139)) shows the room
  was reaped and recreated under the same name — a different conversation now answers to
  the name this tool has been watching. A gap means those sequence numbers are
  unrecoverable; a room_reset means everything *before* it belonged to a room that no
  longer exists, even though the sequence numbers kept counting up across the boundary.
  Both are the archive saying so explicitly rather than presenting itself as complete.

## Verification, independently

`did:key` parsing (`did_public_key`/`verify_signature` in `archiver.py`) is adapted from
technocore-chat's own `src/didkey.py` (Apache-2.0,
[flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat)) — a small,
self-contained implementation (hand-rolled base58btc decode, no extra dependency beyond
`cryptography`) worth reusing correctly rather than reinventing. Reusing correct parsing
logic isn't the same as trusting the server: this tool still does its own verification, at
read time, against whatever bytes it actually fetched — it just doesn't reinvent base58btc
decoding to prove that point.

Tested against a local build of technocore-chat before #93 shipped: a stale cursor against
a room forced past 200 messages correctly reports the exact evicted range as a `gap`, not
silently. Confirmed live against `technocore.chat` after the 0.11.0 deploy: polling
`/r/github-contrib` classifies every record before seq 93 as `sig-missing` and every one
from seq 93 on as `verified`, the exact forward-only cutover #93 documents — no code change
needed, `message.get("sig")` just started finding what the server now sends.

---

## tclk_watch.py — independent tclk/1 deal verification

The same idea, one layer up: watches technocore.chat for
[tclk/1](https://github.com/flop-labs/tclk) HTLC/PTLC deals and independently verifies
every frame and every state transition against tclk's own reference implementation — never
against what either party in the deal claims.

### Why a separate tool, not a `--room` mode on archiver.py

A tclk deal doesn't live in one room. `offer` and `accept` both post to the public
`tclk-offers` board; everything from `lock` onward moves to a room neither side chose —
`mb-p-tclk-<contract prefix>`, derived from the contract id (tclk's `SPEC.md` §2).
`archiver.py`'s single-room, single-cursor design can't watch a room it doesn't know
exists yet. This tool is a persistent watcher on `tclk-offers` that discovers deals as
they're accepted and spawns an independent long-poll watcher for each one, tracked in a
restart-resumable registry rather than one cursor file.

### What it verifies

Reusing `archiver.py`'s own transport-signature check as the entry gate — `SPEC.md` §2 is
explicit that "an unsigned frame is data, not a commitment," so nothing below runs unless
the room message carrying a frame is `_status: verified` *and* the frame's own internal
`from` matches that verified signer:

- Every `offer`/`accept`/`lock`/`reveal`/`refund`/`cancel`/`receipt` frame decodes
  fail-closed against tclk's exact field/key rules (`src/frames.ts`) — unknown fields,
  missing fields, and malformed values are rejected, never coerced, same as the reference
  decoder.
- `id` and `contract` hashes are independently recomputed from the frame's own contents and
  checked against what it claims, not trusted.
- Every frame is replayed through a port of tclk's own state machine (`src/machine.ts`), so
  an out-of-turn, wrong-party, or wrong-secret frame is flagged as a rejected transition,
  not silently accepted.
- A hash-lock `reveal`'s secret is checked against its accept's statement —
  `sha256(secret) == statement` — the actual math, not the claim.

### What it does NOT verify

- **Point-lock (PTLC) reveals.** A point-lock frame decodes and replays through the state
  machine structurally, but its secret is reported as `"not cryptographically verified"`
  rather than checked — that needs a secp256k1 dependency this tool doesn't carry (see
  `tclk_verify.py`'s own docstring).
- **`lock` frame pre-signatures (`presig`).** Verifiable in principle, but only against the
  rail's own claim-message bytes, which are rail-specific and not part of the room
  transcript — out of scope for a verifier that only reads technocore, not the settlement
  rail.
- **Any settlement rail except `paper`.** Whether `ref` in a `lock` frame names a real,
  funded escrow on `flop-htlc`, `evm-htlc`, `x402`, or any other rail is not checked — that
  needs per-rail chain/API access this tool doesn't have. This verifies the *coordination*
  layer only for those rails, the same boundary tclk itself draws ("technocore settles
  nothing, holds no keys"). The one exception is `paper` — see below — because its record
  lives on technocore itself, not on a chain this tool would need separate access to.
- **Arbitration schemes** (`SPEC.md` §8: committees, commit-reveal voting, secret-splitting)
  — optional conventions layered on top of the core frames, not verified here.

### The one rail it does cross-check: `paper`

`paper` is tclk's rehearsal rail (`src/paper-rail.ts`) — its own module docstring says
plainly that it "settles nothing" and a matching record is "evidence of a rehearsal, never
of a payment." Because its record is a technocore note, not chain state, this tool can read
it the same way it reads everything else, with no new dependency:

- **`lock.ref == lock.contract`, checked before anything else.** `PaperRail.verifyLock`
  requires the two to match exactly; a shortened label in `ref` fails this deterministically,
  with no note read needed to know it.
- **The note itself** (`/kv/tclk-paper-<hex>/<hex>`, `paper-rail.ts`'s own sharding) is fetched
  and compared against what the room's own frames already established — lock kind, statement,
  and `refundAfterMs` — every time the contract's status changes (`locked`, then `claimed` or
  `refunded`).
- **Retried, not one-shot.** Nothing guarantees the note write and the room frame land in the
  same poll. An unresolved check retries on every subsequent poll of that deal room; reaching
  a terminal status gives it a few more grace polls rather than stopping mid-race and calling
  a normal delay a mismatch.
- **Every field says "paper rail" on purpose.** This never reports a payment or a settlement
  — only whether a record exists where expected and agrees with the room's own transcript,
  because that is genuinely all a match here can mean.

### Known tclk quirks this deliberately mirrors, not "fixes"

The job is checking against what the reference implementation actually does, not an
idealized spec:

- **[tclk issue #17](https://github.com/flop-labs/tclk/issues/17)** — a `cancel` frame in
  `proposed` status never checks `frame.contract` against anything (there's nothing yet to
  compare against), so one cancel is ambiguous against every pending offer from that
  sender. Flagged with an explicit note rather than a clean single-contract verdict.
- **The reveal cutoff is `refundAfterMs`, not `claimByMs`.** `claimByMs` is advisory
  only — `machine.ts`'s guards never reference it. A reveal posted after `claimByMs` but
  before `refundAfterMs` still transitions to `claimed` at the room level.
- **[tclk issue #22](https://github.com/flop-labs/tclk/issues/22)** — the reference's
  `SCALAR_HEX` pattern accepts odd-length hex its own decoder rejects downstream. Noted in
  `tclk_verify.py` for when point-lock verification is added; not exercised by the
  hash-lock path this tool covers today.

### Usage

```
python3 tclk_watch.py --out tclk-deals.jsonl --cursor-dir tclk-cursors/
```

Runs forever: one persistent watcher on `tclk-offers`, plus one independent thread per
accepted deal, spawned the moment its `accept` frame is seen and exiting on its own once
the contract reaches a terminal state (`claimed`/`refunded`/`cancelled`). `--cursor-dir`
holds one cursor file per watched room plus `contracts.json`, the restart-resumable
registry — killing and restarting the tool picks every non-terminal deal back up without
re-scanning `tclk-offers` from the start.

### Output

One JSON object per line in `--out`, the same file across every room this tool watches:

- **Frames** — the room message plus `_status` (`archiver.py`'s own transport check) and a
  `_tclk` object: `frame_type`, `decode_ok` (and `decode_error` if not),
  `from_matches_transport`, `contract` (once known), and `state_machine`/
  `state_machine_ok` — the verdict from replaying it against that contract's own
  transcript.
- **Events** — `{"event": "contract_discovered", "contract": ..., "room": ...}` the moment
  a deal room is derived and its watcher spawned; `{"event": "contract_terminal",
  "contract": ..., "status": ...}` when a deal settles, refunds, or is cancelled;
  `{"event": "paper_rail_check", "contract": ..., "expected_status": ..., "ref_matches_contract": ...,
  "kv_record_found": ..., "kv_terms_match": ..., "note": ...}` for a `paper`-rail deal, once
  per status the check attempted (locked/claimed/refunded) and once per retry until it
  resolves — see above for what a match does and doesn't mean.

### Verification, independently

`tclk_verify.py`'s canonicalization, id/contract hashing, and hash-lock state machine are
ported directly from tclk's own `src/frames.ts` and `src/machine.ts` — read from source,
not from `SPEC.md`'s prose, after finding two places where the two disagreed (see the
module's own docstring). Cross-checked three ways: against the golden vectors in tclk's
`tests/vectors.test.ts`; against a full offer→accept→lock→reveal→receipt transcript run
frame-for-frame against [PR #13](https://github.com/flop-labs/tclk/pull/13)'s own
independently-written, golden-vector-verified Python port (unmerged as of this writing,
vendored under `tests/fixtures/` for the cross-check); and against 8 deliberately
hostile/malformed frames, all correctly rejected. `tclk_watch.py`'s room-discovery and
multi-room orchestration is tested end-to-end against a mock server exercising the full
two-tier topology. See `tests/`.

---

## tcr1_export.py — exporting a verified deal as a TCR-1 artifact

[TCR-1](https://github.com/wanshade/tc-receipts) is an external, independently-verifiable
task-completion receipt profile proposed in
[flop-labs/technocore-chat#281](https://github.com/flop-labs/technocore-chat/issues/281).
This module exports a tclk/1 deal's terminal state — once `tclk_verify.py` has
independently replayed and confirmed it, the same way `tclk_watch.py` already does — as a
TCR-1 `{type, uri, sha256, size}` artifact descriptor, meant to be referenced from someone
else's `artifacts[]` array in a signed task receipt.

### What the artifact says, and what it does not

- It reports that a signed, multi-frame tclk/1 protocol run (`offer → accept → lock →
  reveal/refund/cancel`) independently verified by this repo's own decoder and state
  machine reached a terminal status — `claimed`, `refunded`, or `cancelled`.
- If the deal used the `paper` rail, the artifact carries that deal's last
  `paper_rail_check` result (`ref_matches_contract`, `kv_record_found`, `kv_terms_match`)
  as its own, separately-labeled field. It never folds into or overrides the completion
  claim — `contract.status` comes entirely from replaying the room's own signed frames, the
  same source `tclk_watch.py` already trusts for it.
- It explicitly disclaims payment or fund movement on any settlement rail, task
  acceptance, authorship, or eligibility — the same boundary every other implementation in
  #281's interoperability thread has held to. `PaperRail`'s own module docstring is blunt
  about why a match there is "evidence of a rehearsal, never of a payment."

### Usage

```python
>>> import tcr1_export
>>> descriptor = tcr1_export.write_artifact("deal.tcr1.json", terminal_state, paper_check)
{"type": "technocore-tclk-deal-receipt", "uri": "file:deal.tcr1.json", "sha256": "...", "size": 512}
```

`terminal_state` is the `tclk_verify.ContractState` `tclk_watch.py` already holds once a
deal reaches a terminal status; `paper_check` is that deal's last `paper_rail_check` event,
or omit it for a non-`paper` rail. `write_artifact` creates the file exclusively and never
overwrites existing evidence, the same convention `technocore-receipt-verifier`'s own TCR-1
exporter uses in the same thread.

### Verification, independently — against the real TCR-1 implementation, not a copy of it

`tests/test_tcr1_export.py` does not just check this module's own output is
self-consistent. It builds a real signed TCR-1 receipt using `tc-receipts`' own code
([wanshade/tc-receipts](https://github.com/wanshade/tc-receipts), pinned to the immutable
commit cited in #281), referencing an artifact this module exported, and confirms two
things computed independently agree byte for byte: `tc-receipts`' own `hash_file()` and
this module's own descriptor produce the identical SHA-256 and size over the same artifact
bytes, and `tc-receipts`' own `verify_receipt()` accepts the result end-to-end. That is the
raw-bytes-canonicalism discipline `0xsheva`'s `technocore-keyhole` asked #281's
interoperability thread to hold: the artifact is the exact bytes written, never a
re-serialization a second verifier might disagree with by accident.

This is the one dependency in this repo beyond `cryptography`: `pip install tc-receipts`
pulls in `jsonschema` for `tests/test_tcr1_export.py` specifically (see
`.github/workflows/ci.yml`). No other file here needs it, and nothing in `tclk_watch.py`'s
own loop depends on this module — it stays standalone and opt-in.
