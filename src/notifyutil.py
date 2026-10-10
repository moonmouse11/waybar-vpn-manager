"""Desktop notifications via notify-send, with untrusted text cleaned first.

Titles and bodies routinely carry text this code doesn't control: a
subscription provider's server name, a key's "#name" fragment (from
whoever sold the key), xray/happd error output. The command is an argv
list (no shell) and "--" ends option parsing, but the text is cleaned
anyway: a leading "-" is dropped outright, control characters can't
smuggle extra lines or terminal escapes, and body markup is escaped —
notification servers (mako, dunst) render <b>/<a>/&entities; in the body,
so "<b>DE</b> & co" would otherwise render bold or as a broken entity.
"""

import contextlib
import html
import re
import subprocess

TITLE_MAXLEN = 100
BODY_MAXLEN = 1000

_TITLE_SPACE = re.compile(r"[\t\n\r\x0b\x0c]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # every C0 control + DEL except \t \n
_TAB = re.compile(r"\t")


def clean_title(text: str) -> str:
    """One line: line breaks/tabs become a space, other controls vanish."""
    text = _CONTROL.sub("", _TITLE_SPACE.sub(" ", text))
    text = re.sub(r" {2,}", " ", text).strip().lstrip("-").strip()
    return text[:TITLE_MAXLEN]


def clean_body(text: str) -> str:
    """Line breaks kept (menu notifications are multi-line), markup escaped."""
    text = _CONTROL.sub("", _TAB.sub(" ", text.replace("\r", "")))
    text = text.strip().lstrip("-").strip()
    return html.escape(text[:BODY_MAXLEN], quote=False)


def send(title: str, message: str, urgent: bool = False) -> None:
    cmd = ["notify-send"]
    if urgent:
        cmd += ["-u", "critical"]
    cmd += ["--", clean_title(title), clean_body(message)]
    # a detached keeper has no one to report a missing notify-send to
    with contextlib.suppress(OSError):
        subprocess.run(cmd, capture_output=True)
