"""Numeric features computed from the page content (HTML, text and scripts)."""

from __future__ import annotations

import math

from preflight.parsing import url_tools as ut

EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".msi", ".apk", ".hta", ".bat", ".cmd", ".ps1",
                         ".vbs", ".jar", ".iso", ".dmg", ".lnk", ".pif", ".img")


def is_executable_url(url: str) -> bool:
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(EXECUTABLE_EXTENSIONS)


def page_features(context) -> dict[str, float]:
    doc = context.doc
    page = context.page

    password_forms = [f for f in doc.forms if f.has_password]
    external_password_forms = [f for f in password_forms if not context.is_same_site(f.action)]
    insecure_password_forms = [f for f in password_forms if f.action.startswith("http://")]
    card_fields = sum(f.card_field_count for f in doc.forms)

    script_urls = doc.external_script_urls
    third_party_scripts = [s for s in script_urls if not context.is_same_site(s)]
    third_party_domains = {ut.registrable_domain(ut.get_host(s)) for s in third_party_scripts}

    external_links = [link for link in doc.links
                      if link.startswith("http") and not context.is_same_site(link)]
    hidden_iframes = [f for f in doc.iframes if f.hidden]
    hidden_cross_site_iframes = [f for f in hidden_iframes
                                 if f.src and not context.is_same_site(f.src)]
    refresh_external = [t for _, t in doc.meta_refresh if t and not context.is_same_site(t)]

    disposition = page.headers.get("content-disposition", "").lower()
    executable_links = [link for link in doc.links if is_executable_url(link)]
    brands_in_text = context.brands_claimed()
    brand_mismatch = bool(brands_in_text) and context.site not in brands_in_text

    return {
        "content_available": float(context.content_analysed),
        "text_length_log": math.log1p(len(doc.text)),
        "link_count_log": math.log1p(len(doc.links)),
        "external_link_ratio": len(external_links) / max(len(doc.links), 1),
        "form_count": float(len(doc.forms)),
        "password_inputs": float(sum(1 for i in doc.all_inputs if i.input_type == "password")),
        "password_form_external_action": float(len(external_password_forms)),
        "password_form_insecure_action": float(len(insecure_password_forms)),
        "card_fields": float(card_fields),
        "title_brand_mismatch": float(brand_mismatch),
        "iframe_count": float(len(doc.iframes)),
        "hidden_iframes": float(len(hidden_iframes)),
        "hidden_cross_site_iframes": float(len(hidden_cross_site_iframes)),
        "iframe_in_overlay": float(sum(1 for f in doc.iframes if f.inside_fixed_overlay)),
        "fixed_overlays": float(doc.fixed_overlays),
        "external_script_count": float(len(script_urls)),
        "third_party_script_domains": float(len(third_party_domains)),
        "inline_event_handlers_log": math.log1p(doc.inline_event_handlers),
        "meta_refresh_external": float(len(refresh_external)),
        "executable_links": float(len(executable_links)),
        "attachment_download": float("attachment" in disposition),
        "binary_executable_response": float(page.binary_signature.endswith("executable")),
        "tls_error": float(page.tls_error),
        "embeds": float(doc.embeds),
    }


def text_features(context) -> dict[str, float]:
    t = context.text
    return {
        "text_urgency": float(t.urgency),
        "text_paste_and_run": float(t.paste_and_run),
        "text_human_check": float(t.human_check),
        "text_tech_support": float(t.tech_support),
        "text_phone_numbers": float(min(t.phone_numbers, 10)),
        "text_fake_update": float(t.fake_update),
        "text_push_bait": float(t.push_bait),
    }


def script_features(context) -> dict[str, float]:
    s = context.scripts
    return {
        "js_chars_log": math.log1p(s.total_chars),
        "js_eval": float(s.eval_calls + s.function_ctor),
        "js_decoders": float(s.atob_calls + s.from_char_code + s.unescape_calls),
        "js_decode_and_run": float(s.decode_and_run),
        "js_document_write": float(s.document_write),
        "js_hex_escape_density": s.hex_escape_density,
        "js_long_strings": float(s.long_strings),
        "js_max_string_entropy": s.max_string_entropy,
        "js_clipboard_write": float(s.clipboard_writes),
        "js_lolbin_terms": float(s.lolbin_terms),
        "js_clipboard_with_command": float(s.clipboard_with_command),
        "js_keylogger_blocks": float(s.keylogger_blocks),
        "js_miner_terms": float(s.miner_terms),
        "js_wasm": float(s.wasm_usage),
        "js_workers": float(s.workers),
        "js_websockets": float(s.websockets),
        "js_fullscreen": float(s.fullscreen),
        "js_alert_loops": float(s.alert_loops),
        "js_before_unload": float(s.before_unload),
        "js_notification_requests": float(s.notification_requests),
        "js_window_opens": float(s.window_opens),
        "js_location_changes": float(s.location_changes),
        "js_executable_strings": float(s.executable_strings),
    }
