"""Phishing checks. Each returns findings with points and a plain-English reason."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .parse import Email, domain_of

BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.co.uk"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com"},
    "office 365": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com"},
    "outlook": {"microsoft.com", "outlook.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com"},
    "netflix": {"netflix.com"},
    "google": {"google.com", "gmail.com", "accounts.google.com"},
    "dhl": {"dhl.com", "dhl.co.uk", "dhl.de"},
    "royal mail": {"royalmail.com"},
    "hmrc": {"gov.uk"},
    "dpd": {"dpd.co.uk", "dpd.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "whatsapp": {"whatsapp.com"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "lloyds": {"lloydsbank.com", "lloydsbank.co.uk", "lloydsbankinggroup.com"},
    "hsbc": {"hsbc.co.uk", "hsbc.com"},
    "natwest": {"natwest.com"},
    "santander": {"santander.co.uk", "santander.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "chase": {"chase.com"},
    "wells fargo": {"wellsfargo.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "mcafee": {"mcafee.com"},
    "norton": {"norton.com", "nortonlifelock.com", "gen.digital"},
    "geek squad": {"bestbuy.com", "geeksquad.com"},
    "trust wallet": {"trustwallet.com"},
}
# Domains of the brands' own names, for lookalike checks ("paypa1.com" vs "paypal").
BRAND_LABELS = {d.split(".")[0] for doms in BRANDS.values() for d in doms if len(d.split(".")[0]) >= 5}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "goo.gl", "rebrand.ly", "shorturl.at", "tiny.cc", "s.id"}
RISKY_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "msi", "lnk", "jar", "com", "cpl", "pif"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlam", "dotm"}
HTML_EXT = {"html", "htm", "shtml", "svg"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "img", "gz", "tar", "cab", "arj"}
SECOND_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "co.jp", "com.br", "co.in", "co.nz", "com.mx", "co.za"}

PRESSURE_PHRASES = [
    r"verify your (account|identity|email)", r"(account|mailbox) (has been |will be )?(suspended|locked|disabled|closed)",
    r"unusual (sign[- ]?in|login|activity)", r"confirm your (password|identity|details|account)",
    r"update (your )?(payment|billing)", r"within (24|48) hours", r"click (here|below|the link)",
    r"mailbox (is )?(full|almost full)", r"(password|account) (will )?expire", r"(gift card|wire transfer|bitcoin)",
    r"(urgent|immediate) action", r"you have (won|been selected)", r"(failed|pending) (delivery|payment)",
    # German, Portuguese and Spanish equivalents seen in real samples
    r"(ihr|dein) konto", r"abgelaufen", r"jetzt (bestätigen|verifizieren|aktualisieren)", r"gesperrt",
    r"sua conta", r"(atualize|confirme) (seus|sua|os)", r"bloquead[oa]", r"su cuenta", r"verifique",
]
LURE_PHRASES = [
    r"free spins", r"freispiele", r"casino", r"jackpot", r"\bbonus\b", r"claim (your|now)",
    r"(subscription|protection|antivirus) (has )?(expired|expires|renewal)", r"(seed|recovery) phrase",
    r"(crypto|bitcoin|wallet) (reward|airdrop|bonus)", r"\bairdrop\b", r"you('ve| have) (won|been chosen)", r"claim (your|the) (prize|reward)", r"prize (draw|winner)",
]
# Top-level domains that abuse researchers (e.g. Spamhaus) repeatedly list as heavily used for spam and phishing.
HIGH_ABUSE_TLDS = {"icu", "top", "xyz", "site", "online", "fit", "click", "link", "work", "rest", "buzz",
                   "cfd", "sbs", "cyou", "monster", "quest", "bond", "lat", "shop", "live"}


@dataclass
class Finding:
    check: str
    points: int
    reason: str


def registrable(host: str) -> str:
    """Approximate the 'owner' part of a hostname (mail.paypal.com -> paypal.com) without a full suffix list."""
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_owned(domain: str, brand: str) -> bool:
    reg = registrable(domain)
    return any(reg == registrable(d) for d in BRANDS[brand])


def _brands_in(text: str) -> set[str]:
    t = text.lower()
    return {b for b in BRANDS if re.search(rf"\b{re.escape(b)}\b", t)}


def check_authentication(e: Email) -> list[Finding]:
    # Only the topmost header was added by our own mail server; lower ones could be written by the sender.
    if not e.auth_results:
        return []
    top = e.auth_results[0].lower()
    out = []
    results = {k: m.group(1) for k in ("spf", "dkim", "dmarc") if (m := re.search(rf"\b{k}=(\w+)", top))}
    if results.get("dmarc") == "fail":
        out.append(Finding("auth", 30, "DMARC failed: the sender domain's own policy says this message isn't genuine"))
    if results.get("spf") in ("fail", "softfail"):
        out.append(Finding("auth", 15 if results["spf"] == "fail" else 8,
                           f"SPF {results['spf']}: the sending server isn't authorised to send for this domain"))
    if results.get("dkim") == "fail":
        out.append(Finding("auth", 10, "DKIM signature failed: the message may have been altered or forged"))
    if results.get("dkim") == "none" and results.get("spf") in (None, "none", "neutral"):
        out.append(Finding("auth", 5, "No DKIM signature and no SPF result: the sender is unauthenticated"))
    # No credit for passing: SPF/DKIM/DMARC prove which domain sent the email, not that the domain is honest.
    # In testing, most missed phishing passed all three from attacker-owned domains.
    return out


def check_sender(e: Email) -> list[Finding]:
    out = []
    fd = e.from_domain
    if not fd:
        return [Finding("sender", 10, "No valid From address")]
    name = e.from_name or ""
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if embedded and registrable(embedded.group(1)) != registrable(fd):
        out.append(Finding("sender", 25, f"Display name shows the address '{embedded.group(0)}' but the real sender is '{e.from_addr}'"))
    for brand in sorted(_brands_in(name)):
        if not _brand_owned(fd, brand):
            out.append(Finding("impersonation", 30, f"Display name mentions '{brand}' but the message comes from {fd}"))
            break
    if fd.startswith("xn--") or ".xn--" in fd:
        out.append(Finding("lookalike", 20, f"Sender domain {fd} uses punycode, often used to imitate real domains"))
    out.extend(_lookalike(fd, "Sender domain"))
    for addr in e.reply_to:
        rd = domain_of(addr)
        if rd and registrable(rd) != registrable(fd):
            out.append(Finding("sender", 15, f"Replies go to {rd}, a different domain from the sender {fd}"))
            break
    rp = domain_of(e.return_path)
    if rp and registrable(rp) != registrable(fd):
        out.append(Finding("sender", 3, f"Bounce address domain ({rp}) differs from the sender (common with mailing services too)"))
    return out


def _lookalike(host: str, label: str) -> list[Finding]:
    reg = registrable(host)
    owned = any(reg == registrable(d) for doms in BRANDS.values() for d in doms)
    if owned:
        return []
    first = reg.split(".")[0]
    for brand_label in BRAND_LABELS:
        if first != brand_label and len(first) >= 4 and _edit_distance(first, brand_label) <= 2 \
                and abs(len(first) - len(brand_label)) <= 2:
            return [Finding("lookalike", 30, f"{label} {reg} looks like '{brand_label}' with small changes")]
        if brand_label in host.replace("-", "").replace(".", "") and brand_label != first:
            return [Finding("lookalike", 20, f"{label} {host} contains the brand name '{brand_label}' but isn't owned by it")]
    return []


def check_links(e: Email) -> list[Finding]:
    out: list[Finding] = []
    flagged = set()

    def add(kind: str, points: int, reason: str):
        if kind not in flagged:
            flagged.add(kind)
            out.append(Finding("links", points, reason))

    for link in e.links:
        url = link.url
        scheme = url.split(":", 1)[0].lower() if ":" in url else ""
        if scheme in ("javascript", "data", "vbscript"):
            add("script", 20, f"A link uses '{scheme}:' which can run code instead of opening a page")
            continue
        host = link.host
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            add("ip", 20, f"A link points straight at an IP address ({defang(host)}) instead of a domain name")
        except ValueError:
            pass
        try:
            if urlsplit(url).username:
                add("userinfo", 20, "A link hides its real destination after an '@' sign")
        except ValueError:
            pass
        if registrable(host) in SHORTENERS:
            add("shortener", 10, f"A link uses the URL shortener {host}, hiding the real destination")
        if host.startswith("xn--") or ".xn--" in host:
            add("punycode", 15, f"A link goes to a punycode domain ({defang(host)}), often used for lookalikes")
        shown = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", link.text.lower())
        if shown and "." in shown.group(1) and registrable(shown.group(1)) != registrable(host):
            add("mismatch", 25, f"Link text shows '{shown.group(1)}' but actually goes to {defang(host)}")
        for f in _lookalike(host, "Link to"):
            add("lookalike", f.points, f.reason)
    return out


def check_attachments(e: Email) -> list[Finding]:
    out = []
    for name in e.attachments:
        parts = name.lower().rsplit(".", 2)
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) == 3 and ext in RISKY_EXT and parts[1] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            out.append(Finding("attachment", 40, f"Attachment '{name}' has a disguised double extension"))
        elif ext in RISKY_EXT:
            out.append(Finding("attachment", 35, f"Attachment '{name}' is a program or script that can run code"))
        elif ext in MACRO_EXT:
            out.append(Finding("attachment", 30, f"Attachment '{name}' is an Office file with macros"))
        elif ext in HTML_EXT:
            out.append(Finding("attachment", 25, f"Attachment '{name}' is a web page, often a fake login form"))
        elif ext in ARCHIVE_EXT:
            out.append(Finding("attachment", 15, f"Attachment '{name}' is an archive or disk image that can hide its contents"))
    return out


def check_language(e: Email) -> list[Finding]:
    text = f"{e.subject}\n{e.text}\n{re.sub(r'<[^>]+>', ' ', e.html)}".lower()
    hits = [p for p in PRESSURE_PHRASES if re.search(p, text)]
    if not hits:
        return []
    return [Finding("language", min(5 * len(hits), 20), f"Pressure or credential language ({len(hits)} pattern(s)), e.g. urgency, account threats, payment requests")]


def check_body_impersonation(e: Email) -> list[Finding]:
    """The email presents itself as a brand (subject or link text), but no sender or link belongs to it.

    A brand only mentioned somewhere in the body is weak evidence: newsletters and mailing lists
    talk about Microsoft or Apple all the time without pretending to be them.
    """
    body = f"{e.text} {re.sub(r'<[^>]+>', ' ', e.html)}"
    presented = _brands_in(e.subject) | _brands_in(" ".join(l.text for l in e.links))
    mentioned = _brands_in(body)
    hosts = {l.host for l in e.links if l.host} | {e.from_domain}
    already = _brands_in(e.from_name or "")
    for brand in sorted(presented - already):
        if not any(_brand_owned(h, brand) for h in hosts if h):
            return [Finding("impersonation", 20, f"Presents itself as '{brand}' (subject or link text) but neither the sender nor any link belongs to {brand}")]
    for brand in sorted(mentioned - presented - already):
        if not any(_brand_owned(h, brand) for h in hosts if h):
            return [Finding("impersonation", 5, f"Mentions '{brand}' in the body, but nothing in the email belongs to {brand}")]
    return []


def check_lures(e: Email) -> list[Finding]:
    text = f"{e.subject} {e.text} {re.sub(r'<[^>]+>', ' ', e.html)}".lower()
    hits = [p for p in LURE_PHRASES if re.search(p, text)]
    if not hits:
        return []
    return [Finding("lure", min(10 * len(hits), 20), f"Classic scam lure ({len(hits)} pattern(s)), e.g. prizes, casino bonuses, expired antivirus, crypto rewards")]


def check_abused_tlds(e: Email) -> list[Finding]:
    hosts = [e.from_domain] + [l.host for l in e.links if l.host]
    bad = sorted({h.rsplit(".", 1)[-1] for h in hosts if h and h.rsplit(".", 1)[-1] in HIGH_ABUSE_TLDS})
    if not bad:
        return []
    return [Finding("tld", 10, f"Uses domain ending(s) {', '.join('.' + t for t in bad)}, heavily abused for spam and phishing")]


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


ALL_CHECKS = [check_authentication, check_sender, check_body_impersonation, check_links, check_attachments,
              check_language, check_lures, check_abused_tlds]
