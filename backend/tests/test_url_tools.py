import unittest

from preflight.parsing import url_tools as ut

PROTECTED = frozenset({"paypal.com", "barclays.co.uk", "northbridge-bank.example"})


class NormaliseUrlTests(unittest.TestCase):
    def test_accepts_http_and_https_and_drops_fragment(self):
        self.assertEqual(ut.normalise_url("HTTPS://Example.COM/a#frag"), "https://example.com/a")
        self.assertEqual(ut.normalise_url("http://example.com"), "http://example.com/")

    def test_rejects_other_schemes(self):
        for bad in ("javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd", "ftp://x.com"):
            with self.assertRaises(ValueError, msg=bad):
                ut.normalise_url(bad)


class DomainTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(ut.registrable_domain("login.secure.example.co.uk"), "example.co.uk")
        self.assertEqual(ut.registrable_domain("paypal.com.account-check.xyz"), "account-check.xyz")
        self.assertEqual(ut.registrable_domain("evil.github.io"), "evil.github.io")
        self.assertEqual(ut.registrable_domain("10.0.0.1"), "10.0.0.1")

    def test_same_site(self):
        self.assertTrue(ut.same_site("https://a.example.com/x", "http://b.example.com/y"))
        self.assertFalse(ut.same_site("https://example.com/", "https://example.org/"))

    def test_subdomain_depth(self):
        self.assertEqual(ut.subdomain_depth("example.com"), 0)
        self.assertEqual(ut.subdomain_depth("a.b.c.example.co.uk"), 3)


class LookalikeTests(unittest.TestCase):
    def test_typosquat_is_detected(self):
        self.assertEqual(ut.find_lookalike("paypa1.com", PROTECTED), "paypal.com")
        self.assertEqual(ut.find_lookalike("barc1ays.top", PROTECTED), "barclays.co.uk")

    def test_homoglyph_punycode_is_detected(self):
        # "pаypal.com" with a Cyrillic "а"
        host = "pаypal.com".encode("idna").decode("ascii")
        self.assertTrue(ut.uses_punycode(host))
        self.assertEqual(ut.find_lookalike(host, PROTECTED), "paypal.com")

    def test_real_domain_is_not_a_lookalike(self):
        self.assertIsNone(ut.find_lookalike("www.paypal.com", PROTECTED))
        self.assertIsNone(ut.find_lookalike("gardening-tips.com", PROTECTED))

    def test_brand_in_someone_elses_url(self):
        self.assertEqual(ut.brand_mentioned_elsewhere(
            "https://paypal.com.secure-check.xyz/login", PROTECTED), "paypal.com")
        self.assertIsNone(ut.brand_mentioned_elsewhere("https://www.paypal.com/signin", PROTECTED))


class HelperTests(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(ut.levenshtein("kitten", "sitting"), 3)
        self.assertEqual(ut.levenshtein("same", "same"), 0)
        self.assertGreater(ut.levenshtein("short", "a-much-longer-word", limit=2), 2)

    def test_entropy_orders_random_above_words(self):
        self.assertGreater(ut.shannon_entropy("x7Qp2Lk9Zr4Tm1Vb"), ut.shannon_entropy("gardengarden"))


if __name__ == "__main__":
    unittest.main()
