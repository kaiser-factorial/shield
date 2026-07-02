"""
Headless-browser / automation watch — detect browser automation running on
this machine (Playwright, Puppeteer, Selenium, bare headless Chromium…).

Why: agents and test runners drive browsers invisibly, and so does malware
or a hijacked automation. A headless browser you didn't start is exactly
the kind of "mysterious activity" worth an event in the shared log.
This is a tripwire, not a blocker — detections are logged, you decide.

Same signatures as the TypeScript version (src/headless.ts).
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

from .logger import emit_event

# Command-line signatures of browser automation. Matching is on the full
# process command line, so install paths count (Playwright/Puppeteer keep
# their browsers under distinctive cache directories).
HEADLESS_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    # The flag itself — any browser (or Electron app) running headless.
    ("headless-flag", re.compile(r"--headless(=\S+)?\b", re.I)),
    # CDP remote debugging — how Puppeteer/CDP clients attach, even to a
    # VISIBLE browser. A headful browser with this flag is still automation.
    ("remote-debug",  re.compile(r"--remote-debugging-(port|pipe)", re.I)),
    # Frameworks, matched via their driver processes and browser cache paths.
    ("playwright",    re.compile(r"playwright", re.I)),
    ("puppeteer",     re.compile(r"puppeteer", re.I)),
    ("webdriver",     re.compile(r"(chromedriver|geckodriver|msedgedriver|operadriver|safaridriver)", re.I)),
    ("selenium",      re.compile(r"selenium", re.I)),
    ("cypress",       re.compile(r"cypress", re.I)),
    ("phantomjs",     re.compile(r"phantomjs", re.I)),
]


def match_headless(command: str) -> list[str]:
    """Labels of every signature the command line matches (empty = clean)."""
    return [label for label, pattern in HEADLESS_SIGNATURES if pattern.search(command)]


@dataclass
class HeadlessProcess:
    pid: int
    ppid: int
    command: str
    labels: list[str]


def scan_headless_processes() -> list[HeadlessProcess]:
    """
    Scan currently running processes for automation signatures.
    Excludes this process itself. macOS/Linux (`ps -axo`).
    """
    out = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        capture_output=True, text=True, check=True,
    ).stdout

    found: list[HeadlessProcess] = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\d+)\s+(.*)$", line)
        if not m:
            continue
        pid, ppid, command = int(m.group(1)), int(m.group(2)), m.group(3)
        if pid == os.getpid():
            continue
        labels = match_headless(command)
        if labels:
            found.append(HeadlessProcess(pid=pid, ppid=ppid, command=command, labels=labels))
    return found


def report_headless(proc: HeadlessProcess) -> None:
    """Emit a `headless_detected` event for a process (persists to the shared log)."""
    emit_event(
        "headless_detected",
        source="headless-watch",
        detail=f"pid={proc.pid} ppid={proc.ppid} [{','.join(proc.labels)}] {proc.command}"[:200],
        patterns=proc.labels,
    )


def scan_and_report() -> list[HeadlessProcess]:
    """One-shot: scan and log every automation process found."""
    procs = scan_headless_processes()
    for p in procs:
        report_headless(p)
    return procs
