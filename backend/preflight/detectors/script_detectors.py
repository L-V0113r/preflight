"""Rules about the page's JavaScript (read statically, never executed)."""

from __future__ import annotations

from preflight.context import ScanContext
from preflight.detectors.base import finding, register
from preflight.features.script_analysis import LOLBIN
from preflight.schema import Severity

SOCIAL = "social-engineering"


@register
def clipboard_command(ctx: ScanContext):
    """'ClickFix': a fake check puts a command on your clipboard and asks you to run it."""
    s, t = ctx.scripts, ctx.text
    social_engineering = bool(t.human_check or t.paste_and_run)
    # Developer docs legitimately offer "copy" buttons for install commands,
    # but they SHOW the command on the page. ClickFix hides it.
    command_visible = bool(LOLBIN.search(ctx.doc.text))
    if s.clipboard_with_command and command_visible and not social_engineering:
        yield finding(
            "js.clipboard_visible_command", "Page has a 'copy command' button",
            "The page can copy a system command that is also shown on the page, as many "
            "software install guides do. Read any command before you run it.",
            Severity.INFO, SOCIAL, s.evidence.get("lolbin", ""))
    elif s.clipboard_with_command:
        yield finding(
            "js.clipboard_command", "Page copies a hidden command to your clipboard",
            "The page's code places a system command (such as PowerShell or mshta) on your "
            "clipboard. Fake 'verify you are human' pages then ask you to paste it into the Run "
            "box, which installs malware. Never paste commands a website gives you.",
            Severity.CRITICAL, SOCIAL, s.evidence.get("lolbin", ""))
    elif t.paste_and_run and (t.human_check or s.clipboard_writes):
        # Without clipboard code this could be an article ABOUT the scam, so
        # it is only MEDIUM; the code (possibly in a script we couldn't
        # fetch) is what makes it HIGH.
        yield finding(
            "text.paste_and_run", "Page tells you to open the Run box and paste something",
            "Instructions like 'press Windows + R, then Ctrl + V' are a hallmark of "
            "'ClickFix' fake-verification scams. No real CAPTCHA works like this.",
            Severity.HIGH if s.clipboard_writes else Severity.MEDIUM, SOCIAL,
            t.evidence.get("paste_and_run", ""))


@register
def keylogger(ctx: ScanContext):
    s = ctx.scripts
    has_card = any(f.card_field_count for f in ctx.doc.forms)
    if s.keylogger_blocks and not has_card:  # the card case is reported by form rules
        yield finding(
            "js.keylogger", "Code records what you type and sends it away",
            "A script listens to key presses or form fields and transmits the values. "
            "Legitimate sites rarely need to do this before you press 'submit'.",
            Severity.HIGH, "data-theft", s.evidence.get("keylogger", ""))


@register
def obfuscated_code(ctx: ScanContext):
    s = ctx.scripts
    packed_strings = s.long_strings >= 1 and s.max_string_entropy >= 5.2
    if s.decode_and_run:
        yield finding(
            "js.decode_and_run", "Hidden code is decoded and run",
            "The page decodes scrambled text (atob / fromCharCode / unescape) and then runs it "
            "(eval / Function / document.write). Attackers do this to hide what the code "
            "does from scanners like this one.",
            Severity.HIGH if packed_strings else Severity.MEDIUM, "obfuscation",
            s.evidence.get("eval") or s.evidence.get("atob", ""))
    elif packed_strings and s.hex_escape_density > 8:
        yield finding(
            "js.packed", "Heavily scrambled JavaScript",
            "The code contains long random-looking strings and dense escape sequences. "
            "Minified code from honest sites can look like this too, so it is a weak signal "
            "on its own.",
            Severity.LOW, "obfuscation", s.evidence.get("long_string", ""))


@register
def cryptominer(ctx: ScanContext):
    s = ctx.scripts
    heavy_compute = s.wasm_usage or s.workers >= 2
    if s.miner_terms and (heavy_compute or s.websockets or s.miner_terms >= 2):
        yield finding(
            "js.cryptominer", "Page would use your computer to mine cryptocurrency",
            "The code contains known browser-mining components. Mining drains battery and "
            "slows your device, and is usually done without consent ('cryptojacking').",
            Severity.HIGH, "cryptojacking", s.evidence.get("miner", ""))


@register
def tech_support_scam(ctx: ScanContext):
    s, t = ctx.scripts, ctx.text
    locking = s.fullscreen + s.alert_loops + s.before_unload
    if t.tech_support and (locking or t.phone_numbers):
        severity = Severity.HIGH if locking and t.phone_numbers else Severity.MEDIUM
        yield finding(
            "page.tech_support_scam", "Fake virus warning / tech-support scam",
            "The page claims your device is infected and asks you to call a number, and "
            + ("tries to lock your browser (full-screen, endless alerts). " if locking else "")
            + "Microsoft, Apple and banks never warn you this way.",
            severity, SOCIAL, t.evidence.get("tech_support", ""))


@register
def notification_bait(ctx: ScanContext):
    s, t = ctx.scripts, ctx.text
    if s.notification_requests and (t.push_bait or t.human_check):
        yield finding(
            "page.push_bait", "Tricks you into allowing notifications",
            "The page says you must click 'Allow' to continue. Allowing lets the site push "
            "scam pop-ups to your desktop even after you leave.",
            Severity.HIGH, SOCIAL, t.evidence.get("push_bait") or t.evidence.get("human_check", ""))
