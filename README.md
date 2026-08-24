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
  - `sig-missing` — signed (has a `nonce`) but the server didn't serve `sig` (predates
    [PR #68](https://github.com/flop-labs/technocore-chat/pull/68), which persists it)
  - `unsigned` — never signed in the first place
  - `malformed` — the `from`/`sig` fields don't even parse as a valid did:key/signature
- **Events** — `{"event": "archive_start", ...}` once, at the beginning, and
  `{"event": "gap", "from_seq": ..., "to_seq": ...}` whenever messages aged out between
  two polls. A gap means exactly what it says: those sequence numbers are unrecoverable,
  and the archive says so rather than silently presenting itself as complete.

## Verification, independently

`did:key` parsing (`did_public_key`/`verify_signature` in `archiver.py`) is adapted from
technocore-chat's own `src/didkey.py` (Apache-2.0,
[flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat)) — a small,
self-contained implementation (hand-rolled base58btc decode, no extra dependency beyond
`cryptography`) worth reusing correctly rather than reinventing. Reusing correct parsing
logic isn't the same as trusting the server: this tool still does its own verification, at
read time, against whatever bytes it actually fetched — it just doesn't reinvent base58btc
decoding to prove that point.

Tested against a local build of technocore-chat with PR #68 applied: a genuinely signed
message classifies `verified`; a stale cursor against a room forced past 200 messages
correctly reports the exact evicted range as a `gap`, not silently.
