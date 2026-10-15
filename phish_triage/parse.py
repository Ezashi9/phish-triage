"""Turn a raw .eml file into the facts the checks need. Static analysis only: nothing is fetched or opened."""
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'()\[\]{}]+""", re.IGNORECASE)
RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\]")


@dataclass
class Link:
    url: str
    text: str = ""

    @property
    def host(self) -> str:
        try:
            return (urlsplit(self.url).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""


@dataclass
class Email:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    auth_results: list[str] = field(default_factory=list)
    received_ips: list[str] = field(default_factory=list)
    text: str = ""
    html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(" >.") if "@" in addr else ""


class _LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


def _decode(part) -> str:
    try:
        return part.get_content()
    except Exception:  # malformed charsets and encodings are normal in phishing mail
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def parse_bytes(raw: bytes) -> Email:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    e = Email()
    e.subject = str(msg.get("Subject", "") or "")
    e.from_name, e.from_addr = parseaddr(str(msg.get("From", "") or ""))
    e.reply_to = [addr for _, addr in getaddresses([str(v) for v in msg.get_all("Reply-To", [])]) if addr]
    e.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1]
    e.auth_results = [str(v) for v in msg.get_all("Authentication-Results", [])]

    for received in msg.get_all("Received", []):
        for ip in RECEIVED_IP_RE.findall(str(received)):
            try:
                if ipaddress.ip_address(ip).is_global:
                    e.received_ips.append(ip)
            except ValueError:
                pass

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            e.attachments.append(filename or "(unnamed)")
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            e.text += _decode(part)
        elif ctype == "text/html":
            e.html += _decode(part)

    if e.html:
        collector = _LinkCollector()
        try:
            collector.feed(e.html)
        except Exception:
            pass
        e.links.extend(l for l in collector.links if l.url)
    seen = {l.url for l in e.links}
    for url in URL_RE.findall(e.text + " " + re.sub(r"<[^>]+>", " ", e.html)):
        url = url.rstrip(".,;:!?")
        if url not in seen:
            e.links.append(Link(url))
            seen.add(url)
    return e


def parse_file(path) -> Email:
    with open(path, "rb") as f:
        return parse_bytes(f.read())
