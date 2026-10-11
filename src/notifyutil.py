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

import html
import re
import subprocess

import logutil

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


def send(
    title: str,
    message: str,
    *,
    urgent: bool = False,
    replace_id: int | None = None,
    expire_ms: int | None = None,
    want_id: bool = False,
) -> int | None:
    """Show a notification. With want_id (Progress only), ask notify-send
    for its id (-p) and update `replace_id` in place (-r); returns the id,
    or None if there's none to be had.

    Plain notifications never pass -p: a notify-send without -p/-r exits on
    the unknown option and shows nothing, which must not take down every
    menu and keeper notification. For want_id calls that fail that way,
    retry without -p/-r — progress then arrives as separate bubbles."""
    flags = []
    if urgent:
        flags += ["-u", "critical"]
    if expire_ms is not None:
        flags += ["-t", str(expire_ms)]
    text = ["--", clean_title(title), clean_body(message)]
    id_flags = []
    if want_id:
        id_flags = ["-p"] + (["-r", str(replace_id)] if replace_id is not None else [])
    result = _run(["notify-send", *id_flags, *flags, *text])
    if want_id and result is not None and result.returncode != 0:
        _run(["notify-send", *flags, *text])
        return None
    if not want_id or result is None:
        return None
    try:
        return int((getattr(result, "stdout", "") or "").strip())
    except ValueError:
        return None


def _run(cmd: list[str]):
    # a detached keeper has no one to report a missing notify-send to
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return None


DONE_EXPIRE_MS = 3000  # a finished tool's last word; its results window takes over


class Progress:
    """One notification per long-running tool, replaced step by step — the
    walker window can't redraw while a tool runs, so this is the spinner.
    Steps stay up until replaced (-t 0); done() expires, fail() is critical
    and carries the reason."""

    def __init__(self, title: str, steps: int | None = None):
        self.title, self.steps = title, steps
        self._id: int | None = None

    def step(self, n: int, message: str) -> None:
        prefix = f"{n}/{self.steps} · " if self.steps else ""
        self._show(prefix + message, expire_ms=0)

    def done(self, message: str) -> None:
        self._show(message, expire_ms=DONE_EXPIRE_MS)

    def fail(self, message: str) -> None:
        # the reason used to live only in the bubble — unrecoverable afterwards
        logutil.log(f"{self.title} failed: {message}")
        self._show(message, urgent=True)

    def _show(self, message: str, urgent: bool = False, expire_ms: int | None = None) -> None:
        nid = send(
            self.title,
            message,
            urgent=urgent,
            replace_id=self._id,
            expire_ms=expire_ms,
            want_id=True,
        )
        if nid is not None:
            self._id = nid
