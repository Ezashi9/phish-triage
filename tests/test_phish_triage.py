"""Unit tests on hand-made emails. All domains are reserved for documentation (RFC 2606) or are the
real brands being imitated; no real phishing content is stored in this repository."""
import unittest

from phish_triage.checks import defang, registrable
from phish_triage.parse import parse_bytes
from phish_triage.triage import triage


def eml(headers: dict, body: str = "Hello", html: str | None = None, attachment: str | None = None) -> bytes:
    lines = [f"{k}: {v}" for k, v in headers.items()]
    if html is None and attachment is None:
        return ("\r\n".join(lines + ["Content-Type: text/plain; charset=utf-8", "", body])).encode()
    b = "BOUNDARY"
    parts = [f"--{b}", "Content-Type: text/plain; charset=utf-8", "", body]
    if html is not None:
        parts += [f"--{b}", "Content-Type: text/html; charset=utf-8", "", html]
    if attachment is not None:
        parts += [f"--{b}", "Content-Type: application/octet-stream",
                  f'Content-Disposition: attachment; filename="{attachment}"', "", "AAAA"]
    parts.append(f"--{b}--")
    return ("\r\n".join(lines + ["MIME-Version: 1.0", f'Content-Type: multipart/mixed; boundary="{b}"', ""] + parts)).encode()


def checks_fired(raw: bytes) -> set[str]:
    return {f.check for f in triage(parse_bytes(raw)).findings if f.points > 0}


class TriageTests(unittest.TestCase):
    def test_normal_email_is_safe(self):
        raw = eml({"From": "Alice <alice@example.com>", "To": "bob@example.com", "Subject": "Lunch on Friday?",
                   "Authentication-Results": "mx.example.net; spf=pass; dkim=pass; dmarc=pass"},
                  "Are you free for lunch on Friday?")
        v = triage(parse_bytes(raw))
        self.assertEqual(v.verdict, "likely safe")

    def test_brand_impersonation_with_failed_dmarc_is_phishing(self):
        raw = eml({"From": '"PayPal Security" <service@account-alerts.example>', "Subject": "Your account has been suspended",
                   "Authentication-Results": "mx.example.net; spf=fail; dkim=none; dmarc=fail"},
                  "Unusual sign-in detected. Verify your account within 24 hours.",
                  html='<a href="http://198.51.100.7/login">https://www.paypal.com/signin</a>')
        v = triage(parse_bytes(raw))
        self.assertEqual(v.verdict, "phishing")
        self.assertTrue({"auth", "impersonation", "links", "language"} <= {f.check for f in v.findings})

    def test_only_topmost_authentication_header_is_trusted(self):
        # The attacker adds a fake "pass" header further down; our server's header (top) says fail.
        raw = eml({"Authentication-Results": "mx.example.net; spf=fail; dkim=fail; dmarc=fail",
                   "X-Filler": "x", "From": "a@example.org"}, "hi")
        raw = raw.replace(b"X-Filler: x", b"Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass")
        self.assertIn("auth", checks_fired(raw))

    def test_link_text_mismatch(self):
        raw = eml({"From": "news@example.com"}, html='<a href="https://evil.example.net/x">www.example.com/account</a>')
        self.assertIn("links", checks_fired(raw))

    def test_matching_link_text_is_fine(self):
        raw = eml({"From": "news@example.com"}, html='<a href="https://www.example.com/a">www.example.com/a</a>')
        self.assertNotIn("links", checks_fired(raw))

    def test_lookalike_sender_domain(self):
        raw = eml({"From": "support@paypa1.com"}, "hello")
        self.assertIn("lookalike", checks_fired(raw))

    def test_real_brand_domain_is_not_a_lookalike(self):
        raw = eml({"From": "PayPal <service@paypal.co.uk>"}, "Your receipt")
        self.assertNotIn("lookalike", checks_fired(raw))
        self.assertNotIn("impersonation", checks_fired(raw))

    def test_reply_to_different_domain(self):
        raw = eml({"From": "ceo@example.com", "Reply-To": "ceo.private@example.net"}, "Please send the payment today")
        self.assertIn("sender", checks_fired(raw))

    def test_display_name_hiding_another_address(self):
        raw = eml({"From": '"security@example.com" <x@example.net>'}, "hi")
        self.assertIn("sender", checks_fired(raw))

    def test_dangerous_attachments(self):
        for name, minimum in [("invoice.pdf.exe", 40), ("statement.html", 25), ("report.docm", 30), ("files.iso", 15)]:
            with self.subTest(name=name):
                v = triage(parse_bytes(eml({"From": "a@example.com"}, "see attached", attachment=name)))
                self.assertGreaterEqual(max(f.points for f in v.findings if f.check == "attachment"), minimum)

    def test_link_tricks(self):
        cases = {
            "ip": '<a href="http://203.0.113.9/x">here</a>',
            "userinfo": '<a href="https://www.example.com@203.0.113.9/x">here</a>',
            "shortener": '<a href="https://bit.ly/abc">here</a>',
            "script": '<a href="javascript:alert(1)">here</a>',
        }
        for name, html in cases.items():
            with self.subTest(trick=name):
                self.assertIn("links", checks_fired(eml({"From": "a@example.com"}, html=html)))

    def test_sender_ips_from_received_headers(self):
        raw = eml({"Received": "from mail.example.net (mail.example.net [8.8.4.4]) by mx.example.com",
                   "From": "a@example.com"}, "hi")
        v = triage(parse_bytes(raw))
        self.assertEqual(v.iocs["sender_ips"], ["8.8.4.4"])

    def test_private_received_ips_are_ignored(self):
        raw = eml({"Received": "from internal ([10.0.0.5]) by mx", "From": "a@example.com"}, "hi")
        self.assertEqual(triage(parse_bytes(raw)).iocs["sender_ips"], [])

    def test_indicators_are_defanged(self):
        self.assertEqual(defang("http://evil.example/x"), "hxxp://evil[.]example/x")
        raw = eml({"From": "a@example.com"}, html='<a href="https://evil.example.net/x">x</a>')
        self.assertEqual(triage(parse_bytes(raw)).iocs["link_domains"], ["evil[.]example[.]net"])

    def test_garbage_input_does_not_crash(self):
        for raw in [b"", b"\x00\xff\xfe garbage", b"From: \r\n\r\n", b"Content-Type: text/html; charset=bogus\r\n\r\n<a href=>"]:
            with self.subTest(raw=raw[:20]):
                triage(parse_bytes(raw))

    def test_dmarc_pass_gives_no_credit(self):
        # Attackers pass DMARC on domains they own, so passing must not lower the score.
        raw = eml({"From": "a@example.com", "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass"}, "hi")
        self.assertEqual(triage(parse_bytes(raw)).score, 0)

    def test_brand_mentioned_in_body_but_not_owned(self):
        raw = eml({"From": "renewals@example.net"}, "Your McAfee protection has expired. Renew today.",
                  html='<a href="https://renew.example.net/x">Renew</a>')
        self.assertIn("impersonation", checks_fired(raw))

    def test_brand_in_subject_scores_more_than_body_mention(self):
        def points(raw):
            return sum(f.points for f in triage(parse_bytes(raw)).findings if f.check == "impersonation")
        presented = eml({"From": "a@example.net", "Subject": "Your McAfee renewal"}, "Renew now")
        mentioned = eml({"From": "a@example.net", "Subject": "Weekly tech news"}, "McAfee released an update today")
        self.assertEqual(points(presented), 20)
        self.assertEqual(points(mentioned), 5)

    def test_brand_mentioned_with_brand_links_is_fine(self):
        raw = eml({"From": "news@example.org"}, "We now accept PayPal.",
                  html='<a href="https://www.paypal.com/uk">PayPal</a>')
        self.assertNotIn("impersonation", checks_fired(raw))

    def test_lure_language(self):
        raw = eml({"From": "a@example.com", "Subject": "Claim your 50 free spins"}, "Casino bonus waiting")
        self.assertIn("lure", checks_fired(raw))

    def test_abused_tld(self):
        raw = eml({"From": "a@example.com"}, html='<a href="https://login.example.icu/x">x</a>')
        self.assertIn("tld", checks_fired(raw))

    def test_malformed_from_header_still_yields_sender(self):
        e = parse_bytes(b"From: Support Team support@example.net (no brackets)\r\n\r\nhi")
        self.assertEqual(e.from_domain, "example.net")

    def test_registrable_domain(self):
        self.assertEqual(registrable("mail.paypal.co.uk"), "paypal.co.uk")
        self.assertEqual(registrable("a.b.example.com"), "example.com")


if __name__ == "__main__":
    unittest.main()
