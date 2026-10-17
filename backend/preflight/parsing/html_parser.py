"""
A tolerant HTML reader built on Python's standard-library HTMLParser.

It never executes anything. It walks the tags once and records only the
things the detectors and features need: forms, inputs, scripts, iframes,
links, meta refreshes, overlays and the visible text.

Malicious pages are often deliberately malformed, so the parser must not
crash on bad markup; HTMLParser is forgiving and we wrap it defensively.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

MAX_TEXT_CHARS = 20_000
MAX_INLINE_SCRIPT_CHARS = 400_000

_INVISIBLE_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)",
    re.IGNORECASE,
)
_FIXED_STYLE = re.compile(r"position\s*:\s*fixed", re.IGNORECASE)
_Z_INDEX = re.compile(r"z-index\s*:\s*(\d+)", re.IGNORECASE)
_PIXEL_SIZE = re.compile(r"(width|height)\s*:\s*(\d+)\s*px", re.IGNORECASE)
_META_REFRESH = re.compile(r"^\s*(\d+)\s*(?:[;,]\s*url\s*=\s*['\"]?([^'\"]+))?", re.IGNORECASE)

# Tags whose text content is not shown to the user.
_NON_VISIBLE_TAGS = frozenset({"script", "style", "noscript", "template", "head", "title"})


@dataclass
class InputField:
    input_type: str
    name: str = ""
    autocomplete: str = ""
    placeholder: str = ""
    element_id: str = ""

    def describes(self, *words: str) -> bool:
        """True if any of `words` appears in the field's name, id, placeholder or autocomplete."""
        blob = f"{self.name} {self.autocomplete} {self.placeholder} {self.element_id}".lower()
        return any(word in blob for word in words)


@dataclass
class FormInfo:
    action: str          # absolute URL the form submits to ('' = same page)
    method: str
    inputs: list[InputField] = field(default_factory=list)

    @property
    def has_password(self) -> bool:
        return any(i.input_type == "password" for i in self.inputs)

    @property
    def card_field_count(self) -> int:
        return sum(1 for i in self.inputs if is_card_field(i))


@dataclass
class ScriptInfo:
    src: str            # absolute URL, or '' for inline scripts
    code: str = ""      # inline code (external code is fetched separately)
    script_type: str = ""


@dataclass
class IframeInfo:
    src: str
    hidden: bool
    width: str = ""
    height: str = ""
    inside_fixed_overlay: bool = False
    # Frames inside <noscript> only load when JavaScript is off; tag managers
    # put a hidden tracking frame there, so these are not counted as hidden.
    in_noscript: bool = False


@dataclass
class PageDocument:
    """The parsed, structured view of one HTML page."""

    base_url: str
    title: str = ""
    forms: list[FormInfo] = field(default_factory=list)
    loose_inputs: list[InputField] = field(default_factory=list)
    scripts: list[ScriptInfo] = field(default_factory=list)
    iframes: list[IframeInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    download_links: list[str] = field(default_factory=list)
    meta_refresh: list[tuple[int, str]] = field(default_factory=list)
    text: str = ""
    headings: list[str] = field(default_factory=list)   # text of <h1>/<h2>
    inline_event_handlers: int = 0
    handler_code: list[str] = field(default_factory=list)  # code in onclick=... etc.
    fixed_overlays: int = 0
    embeds: int = 0
    parse_error: str | None = None

    @property
    def all_inputs(self) -> list[InputField]:
        inputs = list(self.loose_inputs)
        for form in self.forms:
            inputs.extend(form.inputs)
        return inputs

    @property
    def inline_code_blocks(self) -> list[str]:
        """Inline <script> bodies plus inline event-handler code."""
        return [s.code for s in self.scripts if s.code] + list(self.handler_code)

    @property
    def external_script_urls(self) -> list[str]:
        return [s.src for s in self.scripts if s.src]


def is_card_field(field_: InputField) -> bool:
    """Heuristic: does this input collect payment card data?"""
    if field_.autocomplete.lower().startswith("cc-"):
        return True
    return field_.describes("cardnumber", "card_number", "card-number", "ccnum",
                            "cc-number", "cvv", "cvc", "csc", "expiry", "exp-date",
                            "card number", "security code")


def _safe_join(base: str, link: str) -> str:
    link = (link or "").strip()
    if not link:
        return ""
    try:
        return urljoin(base, link)
    except ValueError:
        return ""


class _PageCollector(HTMLParser):
    """Single pass over the HTML, filling a PageDocument as it goes."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.doc = PageDocument(base_url=base_url)
        self._base = base_url
        self._current_form: FormInfo | None = None
        self._tag_stack: list[str] = []
        self._fixed_depth_stack: list[bool] = []
        self._in_title = False
        self._heading_parts: list[str] | None = None
        self._script_buffer: list[str] | None = None
        self._script_meta: ScriptInfo | None = None
        self._text_parts: list[str] = []
        self._text_len = 0

    # ---- helpers -----------------------------------------------------------
    def _inside_fixed_overlay(self) -> bool:
        return any(self._fixed_depth_stack)

    def _add_text(self, text: str) -> None:
        if self._text_len >= MAX_TEXT_CHARS:
            return
        cleaned = " ".join(text.split())
        if cleaned:
            self._text_parts.append(cleaned)
            self._text_len += len(cleaned) + 1

    # ---- HTMLParser callbacks ---------------------------------------------
    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        style = attrs.get("style", "")

        # Inline JavaScript event handlers such as onclick="..." are code too.
        for key, value in attrs.items():
            if key.startswith("on") and value:
                self.doc.inline_event_handlers += 1
                if len(self.doc.handler_code) < 200:
                    self.doc.handler_code.append(value[:5000])

        is_fixed_overlay = False
        if _FIXED_STYLE.search(style):
            z_match = _Z_INDEX.search(style)
            if z_match and int(z_match.group(1)) >= 1000:
                is_fixed_overlay = True
                self.doc.fixed_overlays += 1

        if tag == "base" and attrs.get("href"):
            self._base = _safe_join(self._base, attrs["href"]) or self._base
        elif tag == "title":
            self._in_title = True
        elif tag in ("h1", "h2"):
            self._heading_parts = []
        elif tag == "form":
            action = _safe_join(self._base, attrs.get("action", "")) or self._base
            self._current_form = FormInfo(action=action, method=attrs.get("method", "get").lower())
            self.doc.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select"):
            field_ = InputField(
                input_type=(attrs.get("type") or ("text" if tag == "input" else tag)).lower(),
                name=attrs.get("name", ""),
                autocomplete=attrs.get("autocomplete", ""),
                placeholder=attrs.get("placeholder", ""),
                element_id=attrs.get("id", ""),
            )
            if self._current_form is not None:
                self._current_form.inputs.append(field_)
            else:
                self.doc.loose_inputs.append(field_)
        elif tag == "script":
            src = _safe_join(self._base, attrs.get("src", ""))
            self._script_meta = ScriptInfo(src=src, script_type=attrs.get("type", ""))
            self._script_buffer = []
        elif tag == "iframe" or tag == "frame":
            width, height = attrs.get("width", ""), attrs.get("height", "")
            for prop, value in _PIXEL_SIZE.findall(style):
                if prop.lower() == "width":
                    width = value
                else:
                    height = value
            tiny = width.strip() in {"0", "1"} or height.strip() in {"0", "1"}
            in_noscript = "noscript" in self._tag_stack
            hidden = bool(tiny or "hidden" in attrs or _INVISIBLE_STYLE.search(style))
            self.doc.iframes.append(IframeInfo(
                src=_safe_join(self._base, attrs.get("src", "")),
                hidden=hidden and not in_noscript, width=width, height=height,
                inside_fixed_overlay=self._inside_fixed_overlay() or is_fixed_overlay,
                in_noscript=in_noscript,
            ))
        elif tag == "a":
            href = _safe_join(self._base, attrs.get("href", ""))
            if href:
                self.doc.links.append(href)
                if "download" in attrs:
                    self.doc.download_links.append(href)
        elif tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            match = _META_REFRESH.match(attrs.get("content", ""))
            if match:
                delay = int(match.group(1))
                target = _safe_join(self._base, match.group(2) or "")
                self.doc.meta_refresh.append((delay, target))
        elif tag in ("embed", "object", "applet"):
            self.doc.embeds += 1

        if tag not in _VOID_TAGS:
            self._tag_stack.append(tag)
            self._fixed_depth_stack.append(is_fixed_overlay)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # <input ... /> style tags: treat as a start tag with no body.
        self.handle_starttag(tag, attrs)
        if tag not in _VOID_TAGS and self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
            self._fixed_depth_stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("h1", "h2") and self._heading_parts is not None:
            heading = " ".join(" ".join(self._heading_parts).split())
            if heading and len(self.doc.headings) < 20:
                self.doc.headings.append(heading[:200])
            self._heading_parts = None
        elif tag == "form":
            self._current_form = None
        elif tag == "script" and self._script_meta is not None:
            code = "".join(self._script_buffer or [])[:MAX_INLINE_SCRIPT_CHARS]
            self._script_meta.code = code if not self._script_meta.src else ""
            self.doc.scripts.append(self._script_meta)
            self._script_meta, self._script_buffer = None, None
        # Pop back to the matching open tag (tolerates unclosed children).
        if tag in self._tag_stack:
            while self._tag_stack:
                popped = self._tag_stack.pop()
                self._fixed_depth_stack.pop()
                if popped == tag:
                    break

    def handle_data(self, data: str) -> None:
        if self._script_buffer is not None:
            self._script_buffer.append(data)
            return
        if self._in_title:
            self.doc.title += data
            return
        if not any(t in _NON_VISIBLE_TAGS for t in self._tag_stack):
            self._add_text(data)
            if self._heading_parts is not None:
                self._heading_parts.append(data)

    def finish(self) -> PageDocument:
        # A script left open at end-of-file still counts.
        if self._script_meta is not None:
            self._script_meta.code = "".join(self._script_buffer or [])[:MAX_INLINE_SCRIPT_CHARS]
            self.doc.scripts.append(self._script_meta)
        self.doc.title = " ".join(self.doc.title.split())[:300]
        self.doc.text = " ".join(self._text_parts)[:MAX_TEXT_CHARS]
        return self.doc


_VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})


def parse_html(html: str, base_url: str) -> PageDocument:
    """Parse `html` into a PageDocument. Never raises on bad markup."""
    collector = _PageCollector(base_url)
    try:
        collector.feed(html)
        collector.close()
    except Exception as exc:  # noqa: BLE001 - malformed input must not crash a scan
        doc = collector.finish()
        doc.parse_error = f"{type(exc).__name__}: {exc}"
        return doc
    return collector.finish()
