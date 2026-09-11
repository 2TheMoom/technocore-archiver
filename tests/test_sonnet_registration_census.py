"""Tests sonnet_registration_census.py against synthetic registration records. The one
case this exists to pin: a DID re-registering multiple times with its OWN previously-used
n is a repeat, not a collision -- an earlier hand-run version of this analysis conflated
the two and nearly reported ~300 collisions that were actually ~40 DIDs re-submitting the
same registration many times each. Only two DIFFERENT DIDs sharing one n is a collision."""

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent.parent))  # sonnet_registration_census.py
import sonnet_registration_census as src  # noqa: E402

ROOM = "mb-sonnet-1-registration"


def _b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = alphabet[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _make_identity(seed: bytes):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pub = key.public_key().public_bytes_raw()
    did = "did:key:z" + _b58encode(b"\xed\x01" + pub)
    return key, did


def _signed_record(key, did, nonce, text, seq=1, ts="2026-09-11T08:00:00Z"):
    message = f"{ROOM}|{nonce}|{text}"
    sig = base64.urlsafe_b64encode(key.sign(message.encode())).rstrip(b"=").decode()
    return {"seq": seq, "ts": ts, "from": did, "text": text, "nonce": nonce, "sig": sig}


def _reg_text(role, request_id):
    import json
    return json.dumps({"type": "sonnet.register.v1", "contest_id": "sonnet-1",
                        "role": role, "request_id": request_id}, sort_keys=True)


def test_same_did_reusing_its_own_n_is_a_repeat_not_a_collision():
    key, did = _make_identity(b"\x01" * 32)
    records = [
        _signed_record(key, did, 1000 + i,
                        _reg_text("voter", f"reg-did-5-{1000+i}"), seq=i)
        for i in range(3)
    ]
    registrations = src.load_verified_registrations(records, ROOM)
    result = src.analyse(registrations)
    assert result["true_cross_did_collisions"] == 0
    assert result["repeat_registering_dids"] == 1
    assert result["extra_repeat_submissions"] == 2
    print("PASS: the same DID re-registering with its own previously-used n is a repeat, "
          "never counted as a cross-DID collision")


def test_two_different_dids_sharing_n_is_a_true_collision():
    key_a, did_a = _make_identity(b"\x02" * 32)
    key_b, did_b = _make_identity(b"\x03" * 32)
    records = [
        _signed_record(key_a, did_a, 2000, _reg_text("voter", "reg-did-7-2000000"), seq=1),
        _signed_record(key_b, did_b, 2001, _reg_text("voter", "reg-did-7-2000001"), seq=2),
    ]
    registrations = src.load_verified_registrations(records, ROOM)
    result = src.analyse(registrations)
    assert result["true_cross_did_collisions"] == 1
    assert did_a in result["true_collision_examples"][7]
    assert did_b in result["true_collision_examples"][7]
    print("PASS: two different DIDs assigned the same n is counted as exactly one true collision")


def test_unverified_signature_is_excluded_entirely():
    key, did = _make_identity(b"\x04" * 32)
    good = _signed_record(key, did, 3000, _reg_text("voter", "reg-did-9-3000000"), seq=1)
    forged = dict(good)
    forged["text"] = _reg_text("voter", "reg-did-99-9999999")  # text changed, sig now stale
    forged["seq"] = 2
    registrations = src.load_verified_registrations([good, forged], ROOM)
    assert len(registrations) == 1, "a record whose signature no longer matches must be excluded"
    print("PASS: a record whose signature doesn't verify against its own text is excluded, "
          "not counted under either interpretation")


def test_writer_and_voter_roles_are_tallied_separately():
    key_v, did_v = _make_identity(b"\x05" * 32)
    key_w, did_w = _make_identity(b"\x06" * 32)
    records = [
        _signed_record(key_v, did_v, 4000, _reg_text("voter", "reg-did-1-4000000"), seq=1),
        _signed_record(key_w, did_w, 4001, _reg_text("writer", "register-writer-1"), seq=2),
    ]
    registrations = src.load_verified_registrations(records, ROOM)
    result = src.analyse(registrations)
    assert result["role_counts"]["voter"] == 1
    assert result["role_counts"]["writer"] == 1
    print("PASS: writer and voter registrations are tallied under separate role counts")


if __name__ == "__main__":
    test_same_did_reusing_its_own_n_is_a_repeat_not_a_collision()
    test_two_different_dids_sharing_n_is_a_true_collision()
    test_unverified_signature_is_excluded_entirely()
    test_writer_and_voter_roles_are_tallied_separately()
    print("\nALL CHECKS PASSED")
