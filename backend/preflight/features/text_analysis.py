"""
Phrase-level analysis of the visible page text.

Social-engineering attacks are written for humans, so the words on the page
are evidence too: "Press Windows + R", "your computer is infected, call...",
"your account will be suspended". Each group of phrases is a small, readable
list you can extend.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_I = re.IGNORECASE

URGENCY = re.compile(
    r"account (?:will be|has been) (?:suspended|locked|limited|closed)|"
    r"verify (?:your|ur) (?:account|identity|information) (?:now|immediately|within)|"
    r"within 24 hours|unusual (?:sign[- ]in )?activity|immediate action required|"
    r"failure to (?:verify|comply)|confirm your (?:payment|billing) details|"
    r"your (?:parcel|package|delivery) (?:is on hold|could not be delivered)|"
    r"final (?:warning|notice)",
    _I)

# Paste-and-run ("ClickFix") instructions: open the Run box and paste.
PASTE_AND_RUN = re.compile(
    r"(?:windows|win|⊞)\s*(?:key)?\s*\+\s*r\b|press\s+(?:the\s+)?windows\s+key|"
    r"ctrl\s*\+\s*v|paste (?:it|the code|the command)|open (?:the )?run (?:dialog|box)|"
    r"terminal and paste|cmd\s*\+\s*space",
    _I)
HUMAN_CHECK = re.compile(
    r"verify (?:you are|that you are|you're) (?:a )?human|i'?m not a robot|"
    r"verification steps?|complete (?:the )?verification|captcha",
    _I)

TECH_SUPPORT = re.compile(
    r"(?:your )?(?:computer|pc|device|system) (?:is|has been) (?:infected|blocked|locked|compromised)|"
    r"call (?:microsoft|apple|windows) support|do not (?:close|restart) (?:this|your)|"
    r"(?:toll[- ]free|helpline)|virus(?:es)? (?:detected|found)|error code\s*#?\s*\w{3,}",
    _I)
PHONE_NUMBER = re.compile(r"(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3,4}\)?[\s\-.]?\d{3}[\s\-.]?\d{3,4}")

FAKE_UPDATE = re.compile(
    r"(?:your )?(?:browser|chrome|firefox|edge|flash player|video player) "
    r"(?:is out of date|needs (?:an )?update|update required)|"
    r"(?:critical|security) update (?:required|available)|install (?:the )?(?:latest )?update",
    _I)

PUSH_BAIT = re.compile(
    r"(?:click|press|tap) (?:\"|')?allow(?:\"|')? to (?:continue|verify|confirm|watch|download|prove)",
    _I)


@dataclass
class TextProfile:
    urgency: int = 0
    paste_and_run: int = 0
    human_check: int = 0
    tech_support: int = 0
    phone_numbers: int = 0
    fake_update: int = 0
    push_bait: int = 0
    evidence: dict[str, str] = field(default_factory=dict)


def _hits(pattern: re.Pattern[str], text: str, profile: TextProfile, key: str) -> int:
    matches = list(pattern.finditer(text))
    if matches:
        profile.evidence.setdefault(key, matches[0].group(0)[:80])
    return len(matches)


def analyse_text(text: str) -> TextProfile:
    profile = TextProfile()
    profile.urgency = _hits(URGENCY, text, profile, "urgency")
    profile.paste_and_run = _hits(PASTE_AND_RUN, text, profile, "paste_and_run")
    profile.human_check = _hits(HUMAN_CHECK, text, profile, "human_check")
    profile.tech_support = _hits(TECH_SUPPORT, text, profile, "tech_support")
    profile.phone_numbers = len(PHONE_NUMBER.findall(text))
    profile.fake_update = _hits(FAKE_UPDATE, text, profile, "fake_update")
    profile.push_bait = _hits(PUSH_BAIT, text, profile, "push_bait")
    return profile
