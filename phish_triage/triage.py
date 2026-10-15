from dataclasses import dataclass, field

from .checks import ALL_CHECKS, Finding, defang, registrable
from .parse import Email

PHISHING_AT = 50
SUSPICIOUS_AT = 25


@dataclass
class Verdict:
    verdict: str
    score: int
    findings: list[Finding]
    iocs: dict = field(default_factory=dict)


def triage(e: Email) -> Verdict:
    findings = [f for check in ALL_CHECKS for f in check(e)]
    findings.sort(key=lambda f: -f.points)
    score = max(sum(f.points for f in findings), 0)
    verdict = "phishing" if score >= PHISHING_AT else "suspicious" if score >= SUSPICIOUS_AT else "likely safe"
    hosts = sorted({l.host for l in e.links if l.host})
    iocs = {
        "sender": defang(e.from_addr),
        "sender_ips": sorted(set(e.received_ips)),
        "link_domains": [defang(h) for h in hosts],
        "link_registrable_domains": sorted({defang(registrable(h)) for h in hosts}),
        "attachments": e.attachments,
    }
    return Verdict(verdict, score, findings, iocs)
