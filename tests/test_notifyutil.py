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
    assert calls == [["notify-send", "-u", "critical", "--", "t", "&lt;x&gt;\n-y"]]


def test_send_survives_missing_notify_send(monkeypatch):
    def missing(cmd, **kw):
        raise FileNotFoundError("notify-send")

    monkeypatch.setattr(subprocess, "run", missing)
    notifyutil.send("t", "m")  # must not raise out of a detached keeper
