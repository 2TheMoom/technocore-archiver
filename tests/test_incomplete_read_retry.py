"""Tests that http.client.IncompleteRead (a connection dropped mid-response) is retried,
not left to crash the archiver -- seen live: it is not a subclass of OSError, so the
existing `except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError)`
clause never caught it, and the whole process died on what should have been an ordinary
retry, same as a plain connection reset already was.
"""

import http.client
import shutil
import sys
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # archiver.py
import archiver as base  # noqa: E402


def test_archiver_run_retries_past_an_incomplete_read():
    tmp = Path("/tmp/incomplete_read_archiver_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    calls = {"n": 0}
    empty_view = {"messages": [], "last_seq": 0, "generation": 1}

    def flaky_fetch(url, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http.client.IncompleteRead(b"partial", 100)
        return empty_view

    class Args:
        room = "lobby"
        base_url = "http://127.0.0.1:0"
        wait = 0.1
        out = str(tmp / "out.jsonl")
        cursor_file = str(tmp / "out.jsonl.cursor")
        once = True

    with unittest.mock.patch.object(base, "fetch_json", flaky_fetch), \
         unittest.mock.patch.object(base.time, "sleep", lambda s: None):
        base.run(Args)

    assert calls["n"] == 2, f"expected exactly one failure then one success, got {calls['n']} calls"
    print("PASS: an IncompleteRead on the first poll is retried, and the second, "
          "successful poll completes --once cleanly")


def test_tclk_watch_poll_retries_past_an_incomplete_read():
    import tclk_watch as tw

    tmp = Path("/tmp/incomplete_read_tclk_watch_test")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    calls = {"n": 0}
    empty_view = {"messages": [], "last_seq": 0, "generation": 1}

    def flaky_fetch(url, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http.client.IncompleteRead(b"partial", 100)
        return empty_view

    stop = __import__("threading").Event()

    def on_message(message):
        pass

    def stop_after_one_success(*a, **kw):
        stop.set()

    with unittest.mock.patch.object(base, "fetch_json", flaky_fetch), \
         unittest.mock.patch.object(tw.time, "sleep", lambda s: None):
        tw.watch_room("lobby", "http://127.0.0.1:0", 0.1, tmp, on_message, stop,
                      label="test", on_poll=stop_after_one_success)

    assert calls["n"] == 2, f"expected exactly one failure then one success, got {calls['n']} calls"
    print("PASS: tclk_watch's own poll loop retries an IncompleteRead the same way")


if __name__ == "__main__":
    test_archiver_run_retries_past_an_incomplete_read()
    test_tclk_watch_poll_retries_past_an_incomplete_read()
    print("\nALL CHECKS PASSED")
