"""
Static JavaScript analysis: read the code as text and count tell-tale
patterns, without ever running it.

Running untrusted JavaScript safely needs a full sandboxed browser, which is
slow and heavy. Static analysis is fast and safe, but can be fooled by heavy
obfuscation; that is why obfuscation itself is something we measure.

Each script block is analysed on its own (so "listens to key presses" and
"sends data away" must happen in the SAME script to look like a keylogger),
and the results are added up into one ScriptProfile for the whole page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from collections.abc import Callable

from preflight.parsing.url_tools import shannon_entropy

_I = re.IGNORECASE

EVAL = re.compile(r"\beval\s*\(")
FUNCTION_CTOR = re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]")
ATOB = re.compile(r"\batob\s*\(")
FROM_CHAR_CODE = re.compile(r"fromCharCode\s*\(")
UNESCAPE = re.compile(r"\bunescape\s*\(")
DOCUMENT_WRITE = re.compile(r"document\.write(?:ln)?\s*\(")
HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
LONG_STRING = re.compile(r"(['\"`])([A-Za-z0-9+/=_\-%\\]{200,})\1")

CLIPBOARD_WRITE = re.compile(
    r"navigator\.clipboard\.writeText|execCommand\s*\(\s*['\"]copy['\"]|clipboardData\.setData")
# Windows/Unix "living off the land" tools used in paste-and-run attacks.
LOLBIN = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh|mshta(?:\.exe)?|certutil|bitsadmin|rundll32|"
    r"regsvr32|wscript|cscript|invoke-expression|invoke-webrequest|iex|iwr)\b"
    r"|cmd(?:\.exe)?\s+/c|-enc(?:odedcommand)?\s|-w(?:indowstyle)?\s+h(?:idden)?\b"
    r"|curl\s+-s[^\n]{0,80}\|\s*(?:ba)?sh",
    _I)

KEY_LISTENER = re.compile(
    r"addEventListener\s*\(\s*['\"](?:keydown|keypress|keyup|input|change|blur)['\"]"
    r"|\.on(?:keydown|keypress|keyup|input|change)\s*=")
READS_VALUES = re.compile(r"\.value\b|\.key\b|FormData\s*\(")
# "Strong" exfiltration channels are rarely used for honest form handling.
EXFIL_STRONG = re.compile(
    r"new\s+Image\s*\(\s*\)|\.src\s*=\s*[^;\n]{0,120}\+|sendBeacon\s*\(")
# "Weak" channels are everywhere (search suggestions, autosave), so they only
# count when the same script also mentions a URL on a different site.
EXFIL_WEAK = re.compile(r"XMLHttpRequest|fetch\s*\(|WebSocket\s*\(")
ABSOLUTE_URL = re.compile(r"(?:https?|wss?)://([a-z0-9.\-]+)", re.IGNORECASE)

MINER = re.compile(
    r"coinhive|coin-hive|cryptonight|cryptoloot|crypto-loot|coinimp|webminepool|"
    r"deepminer|jsecoin|stratum\+tcp|hashespersecond|miner\.start\s*\(|"
    r"\bminer\s*=\s*new\b|cryptoNightHash",
    _I)
WASM = re.compile(r"WebAssembly\.(?:instantiate|compile|Module|instantiateStreaming)")
WORKER = re.compile(r"new\s+(?:Shared)?Worker\s*\(")
WEBSOCKET = re.compile(r"new\s+WebSocket\s*\(")

FULLSCREEN = re.compile(r"requestFullscreen|webkitRequestFullscreen|mozRequestFullScreen")
ALERT_LOOP = re.compile(
    r"(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\)|setInterval\s*\()"
    r"[\s\S]{0,200}?\b(?:alert|confirm|prompt)\s*\(")
BEFORE_UNLOAD = re.compile(r"onbeforeunload|addEventListener\s*\(\s*['\"]beforeunload")
NOTIFICATION = re.compile(r"Notification\.requestPermission|pushManager\.subscribe")
WINDOW_OPEN = re.compile(r"window\.open\s*\(")
LOCATION_CHANGE = re.compile(
    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=(?!=)|location\.(?:replace|assign)\s*\(")
EXECUTABLE_IN_STRING = re.compile(
    r"\.(?:exe|scr|msi|apk|hta|bat|cmd|ps1|vbs|jar|iso|dmg|lnk|pif)(?:['\"?#]|$)", _I)


@dataclass
class ScriptProfile:
    """Counts and flags describing all JavaScript on one page."""

    total_chars: int = 0
    blocks: int = 0
    eval_calls: int = 0
    function_ctor: int = 0
    atob_calls: int = 0
    from_char_code: int = 0
    unescape_calls: int = 0
    document_write: int = 0
    hex_escapes: int = 0
    long_strings: int = 0
    max_string_entropy: float = 0.0
    clipboard_writes: int = 0
    lolbin_terms: int = 0
    clipboard_with_command: int = 0     # blocks that write a shell command to the clipboard
    keylogger_blocks: int = 0           # blocks that read keys/values AND send data out
    miner_terms: int = 0
    wasm_usage: int = 0
    workers: int = 0
    websockets: int = 0
    fullscreen: int = 0
    alert_loops: int = 0
    before_unload: int = 0
    notification_requests: int = 0
    window_opens: int = 0
    location_changes: int = 0
    executable_strings: int = 0
    decode_and_run: int = 0             # blocks that decode a string AND run code
    evidence: dict[str, str] = field(default_factory=dict)

    @property
    def hex_escape_density(self) -> float:
        """Hex/unicode escapes per 1,000 characters of code."""
        return 1000.0 * self.hex_escapes / max(self.total_chars, 1)



def _snippet(code: str, match: re.Match[str], width: int = 80) -> str:
    start = max(match.start() - 20, 0)
    text = code[start:start + width]
    return " ".join(text.split())


def analyse_scripts(code_blocks: list[str],
                    is_same_site: Callable[[str], bool] | None = None) -> ScriptProfile:
    """
    Analyse every script block and combine the results.

    `is_same_site(url)` tells us whether a URL belongs to the page's own site;
    without it, every absolute URL is treated as off-site.
    """
    same_site = is_same_site or (lambda _url: False)
    profile = ScriptProfile()
    for code in code_blocks:
        if not code:
            continue
        profile.blocks += 1
        profile.total_chars += len(code)
        _analyse_block(code, profile, same_site)
    return profile


def _count(pattern: re.Pattern[str], code: str, profile: ScriptProfile, key: str) -> int:
    """Count matches and remember the first one as evidence."""
    matches = list(pattern.finditer(code))
    if matches and key not in profile.evidence:
        profile.evidence[key] = _snippet(code, matches[0])
    return len(matches)


def _sends_data_off_site(code: str, same_site: Callable[[str], bool]) -> re.Match[str] | None:
    strong = EXFIL_STRONG.search(code)
    if strong:
        return strong
    weak = EXFIL_WEAK.search(code)
    if weak and any(not same_site(f"https://{host}/") for host in ABSOLUTE_URL.findall(code)):
        return weak
    return None


def _analyse_block(code: str, p: ScriptProfile, same_site: Callable[[str], bool]) -> None:
    evals = _count(EVAL, code, p, "eval")
    ctors = _count(FUNCTION_CTOR, code, p, "function_ctor")
    atobs = _count(ATOB, code, p, "atob")
    char_codes = _count(FROM_CHAR_CODE, code, p, "from_char_code")
    unescapes = _count(UNESCAPE, code, p, "unescape")
    writes = _count(DOCUMENT_WRITE, code, p, "document_write")
    p.eval_calls += evals
    p.function_ctor += ctors
    p.atob_calls += atobs
    p.from_char_code += char_codes
    p.unescape_calls += unescapes
    p.document_write += writes
    # Classic packed loader: decode a string and run it, in the same script.
    # (Decoding is often immediately wrapped by the runner: eval(atob(...)).)
    if (atobs or char_codes or unescapes) and (evals or ctors):
        p.decode_and_run += 1
    p.hex_escapes += len(HEX_ESCAPE.findall(code))

    for match in LONG_STRING.finditer(code):
        p.long_strings += 1
        entropy = shannon_entropy(match.group(2)[:2000])
        if entropy > p.max_string_entropy:
            p.max_string_entropy = entropy
            p.evidence["long_string"] = match.group(2)[:60] + "..."

    clipboard = _count(CLIPBOARD_WRITE, code, p, "clipboard")
    lolbins = _count(LOLBIN, code, p, "lolbin")
    p.clipboard_writes += clipboard
    p.lolbin_terms += lolbins
    if clipboard and lolbins:
        p.clipboard_with_command += 1

    if KEY_LISTENER.search(code) and READS_VALUES.search(code):
        exfil = _sends_data_off_site(code, same_site)
        if exfil:
            p.keylogger_blocks += 1
            p.evidence.setdefault("keylogger", _snippet(code, exfil))

    p.miner_terms += _count(MINER, code, p, "miner")
    p.wasm_usage += _count(WASM, code, p, "wasm")
    p.workers += _count(WORKER, code, p, "worker")
    p.websockets += _count(WEBSOCKET, code, p, "websocket")
    p.fullscreen += _count(FULLSCREEN, code, p, "fullscreen")
    p.alert_loops += _count(ALERT_LOOP, code, p, "alert_loop")
    p.before_unload += _count(BEFORE_UNLOAD, code, p, "before_unload")
    p.notification_requests += _count(NOTIFICATION, code, p, "notification")
    p.window_opens += _count(WINDOW_OPEN, code, p, "window_open")
    p.location_changes += _count(LOCATION_CHANGE, code, p, "location_change")
    p.executable_strings += _count(EXECUTABLE_IN_STRING, code, p, "executable_string")
