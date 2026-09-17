"""Tests Cursor.write()'s retry against a transient Windows PermissionError -- the same
class of failure already fixed in tclk_watch.py's ContractRegistry._flush, but seen live
on a different call: archiver.py crashed writing its own cursor file with
`PermissionError: ... kibble_archive.jsonl.cursor.tmp`, failing inside write_text itself,
not only the rename step the original fix targeted. This covers both failure points.
"""

import shutil
import sys
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # archiver.py
import archiver as base  # noqa: E402


def test_cursor_write_retries_a_transient_permission_error_on_write_text():
    """The failure point observed live: opening/writing the .tmp file itself, not the
    rename. Must be retried, same as the rename already was."""
    tmp_dir = Path("/tmp/archiver_cursor_write_test")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    cursor = base.Cursor(tmp_dir / "out.jsonl.cursor")

    real_write_text = Path.write_text
    calls = {"n": 0}

    def flaky_write_text(self, data, encoding=None, errors=None, newline=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("Access is denied")
        return real_write_text(self, data, encoding=encoding, errors=errors, newline=newline)

    with unittest.mock.patch.object(Path, "write_text", flaky_write_text):
        cursor.write(42, 1)

    assert calls["n"] == 3, "expected exactly two failures before the third attempt succeeded"
    assert cursor.read() == (42, 1)
    print("PASS: a transient PermissionError while writing the cursor's .tmp file is "
          "retried, not left to crash the archiver")


def test_cursor_write_retries_a_transient_permission_error_on_replace():
    """The original failure point this pattern was written for: the atomic rename."""
    tmp_dir = Path("/tmp/archiver_cursor_replace_test")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    cursor = base.Cursor(tmp_dir / "out.jsonl.cursor")

    real_replace = Path.replace
    calls = {"n": 0}

    def flaky_replace(self, target):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("Access is denied")
        return real_replace(self, target)

    with unittest.mock.patch.object(Path, "replace", flaky_replace):
        cursor.write(7, None)

    assert calls["n"] == 3
    assert cursor.read() == (7, None)
    print("PASS: a transient PermissionError during the atomic rename is retried too")


def test_cursor_write_reraises_after_exhausting_retries():
    """A persistent lock must still fail loudly -- the retry tolerates a race, not a
    promise to wait forever."""
    tmp_dir = Path("/tmp/archiver_cursor_persistent_test")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    cursor = base.Cursor(tmp_dir / "out.jsonl.cursor")

    def always_locked(self, data, encoding=None, errors=None, newline=None):
        raise PermissionError("Access is denied")

    raised = False
    with unittest.mock.patch.object(Path, "write_text", always_locked):
        try:
            cursor.write(1, None)
        except PermissionError:
            raised = True
    assert raised, "a persistent lock must still raise, not be swallowed or hang"
    print("PASS: a persistent PermissionError still raises once retries are exhausted")


if __name__ == "__main__":
    test_cursor_write_retries_a_transient_permission_error_on_write_text()
    test_cursor_write_retries_a_transient_permission_error_on_replace()
    test_cursor_write_reraises_after_exhausting_retries()
    print("\nALL CHECKS PASSED")
