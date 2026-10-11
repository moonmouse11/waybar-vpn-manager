import subprocess

import notifyutil


def test_title_is_one_clean_line():
    assert notifyutil.clean_title("VLESS\n— tunnel\x1b[31m lost\t") == "VLESS — tunnel[31m lost"


def test_leading_dashes_can_never_reach_notify_send_as_an_option():
    # a key's "#name" fragment comes from whoever sold the key
    assert notifyutil.clean_title("--app-name=evil") == "app-name=evil"
    assert notifyutil.clean_body("  -u low: server") == "u low: server"


def test_body_keeps_line_breaks_but_drops_other_control_chars():
    # menu notifications are built with "\n".join(lines)
    assert notifyutil.clean_body("a\nb\r\x00c\x07") == "a\nbc"


def test_body_markup_is_escaped():
    # notification servers (mako, dunst) render body markup: a server named
    # "<b>DE</b> & co" must show as text, not bold / a broken entity
    assert notifyutil.clean_body("<b>DE</b> & co") == "&lt;b&gt;DE&lt;/b&gt; &amp; co"


def test_title_markup_is_left_alone():
    # the spec renders markup in the body only; escaping the title would
    # show a literal "&amp;"
    assert notifyutil.clean_title("Happ · A & B") == "Happ · A & B"


def test_lengths_are_capped():
    assert len(notifyutil.clean_title("x" * 1000)) == notifyutil.TITLE_MAXLEN
    assert len(notifyutil.clean_body("x" * 10000)) == notifyutil.BODY_MAXLEN


def test_send_passes_cleaned_text_after_double_dash(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    notifyutil.send("-t", "<x>\n-y", urgent=True)
    # plain notifications never ask for an id: no -p, exactly as before Progress
    assert calls == [["notify-send", "-u", "critical", "--", "t", "&lt;x&gt;\n-y"]]


def test_send_survives_missing_notify_send(monkeypatch):
    def missing(cmd, **kw):
        raise FileNotFoundError("notify-send")

    monkeypatch.setattr(subprocess, "run", missing)
    notifyutil.send("t", "m")  # must not raise out of a detached keeper


class _NotifySend:
    """Records notify-send argv; answers --print-id with a fixed id."""

    def __init__(self, nid="42"):
        self.calls, self.nid = [], nid

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, f"{self.nid}\n", "")


def test_progress_updates_one_notification_in_place(monkeypatch):
    """walker -d can't redraw while a tool runs, so progress is one
    notification replaced step by step (-p prints its id, -r reuses it)."""
    ns = _NotifySend()
    monkeypatch.setattr(subprocess, "run", ns)
    p = notifyutil.Progress("DNS Leak Test", steps=3)
    p.step(1, "requesting a test id")
    p.step(2, "sending 30 DNS probes")
    first, second = ns.calls
    assert "-p" in first and "-r" not in first
    assert first[-1] == "1/3 · requesting a test id"
    assert second[second.index("-r") + 1] == "42"  # same bubble, replaced
    assert second[-1] == "2/3 · sending 30 DNS probes"
    assert first[first.index("-t") + 1] == "0"  # stays up while the step runs


def test_progress_fail_replaces_it_with_a_critical_reason(monkeypatch):
    ns = _NotifySend()
    monkeypatch.setattr(subprocess, "run", ns)
    p = notifyutil.Progress("DNS Leak Test", steps=3)
    p.step(1, "requesting a test id")
    p.fail("failed at 1/3: TLS handshake timed out")
    last = ns.calls[-1]
    assert last[last.index("-r") + 1] == "42"
    assert last[last.index("-u") + 1] == "critical"
    assert last[-1] == "failed at 1/3: TLS handshake timed out"


def test_progress_done_expires(monkeypatch):
    ns = _NotifySend()
    monkeypatch.setattr(subprocess, "run", ns)
    p = notifyutil.Progress("IP Info")
    p.step(1, "detecting your IP")
    p.done("done")
    last = ns.calls[-1]
    assert last[last.index("-t") + 1] == str(notifyutil.DONE_EXPIRE_MS)
    assert "-u" not in last


def test_progress_survives_missing_notify_send_and_garbage_ids(monkeypatch):
    def missing(cmd, **kw):
        raise FileNotFoundError("notify-send")

    monkeypatch.setattr(subprocess, "run", missing)
    notifyutil.Progress("t", steps=2).step(1, "x")  # no raise
    ns = _NotifySend(nid="not-a-number")
    monkeypatch.setattr(subprocess, "run", ns)
    p = notifyutil.Progress("t", steps=2)
    p.step(1, "x")
    p.step(2, "y")
    assert "-r" not in ns.calls[1]  # no usable id -> a fresh bubble, never a crash


def test_progress_falls_back_when_notify_send_rejects_print_id(monkeypatch):
    """A notify-send without -p/-r exits on the unknown option and shows
    nothing — progress (incl. the final critical reason) must still show up,
    as separate bubbles."""
    calls = []

    def old_notify_send(cmd, **kw):
        calls.append(cmd)
        rc = 1 if ("-p" in cmd or "-r" in cmd) else 0
        return subprocess.CompletedProcess(cmd, rc, "", "Unknown option -p" if rc else "")

    monkeypatch.setattr(subprocess, "run", old_notify_send)
    p = notifyutil.Progress("DNS Leak Test", steps=3)
    p.step(1, "requesting a test id")
    p.fail("failed at 1/3: timed out")
    shown = [c for c in calls if "-p" not in c and "-r" not in c]
    assert [c[-1] for c in shown] == ["1/3 · requesting a test id", "failed at 1/3: timed out"]
    assert "critical" in shown[-1]


def test_progress_fail_logs_the_reason(monkeypatch):
    logged = []
    monkeypatch.setattr(notifyutil.logutil, "log", logged.append)
    monkeypatch.setattr(notifyutil, "send", lambda *a, **k: None)
    notifyutil.Progress("DNS Leak Test").fail("Test failed at 1/3: timed out")
    assert logged == ["DNS Leak Test failed: Test failed at 1/3: timed out"]
