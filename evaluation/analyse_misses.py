"""Describe the phishing emails the tool missed, as aggregate counts only (no addresses, bodies or links)."""
import re
from collections import Counter
from pathlib import Path

from phish_triage.checks import registrable
from phish_triage.parse import parse_file
from phish_triage.triage import triage

DATA = Path(__file__).resolve().parent / "data"
LANG_HINTS = {
    "portuguese": ["você", "sua conta", "clique", "senha", "prezado", "pagamento"],
    "spanish": ["usted", "su cuenta", "haga clic", "contraseña", "estimado"],
    "english": ["your account", "click", "password", "dear", "please"],
}


def tld(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else "(none)"


def main() -> None:
    stats = {k: Counter() for k in ("auth_present", "spf", "dkim", "dmarc", "links", "link_tlds", "from_tld",
                                    "language", "has_html", "attachment_ext", "score", "subject_words", "auth_trust")}
    missed = 0
    for f in sorted((DATA / "phishing").glob("*.eml")):
        e = parse_file(f)
        v = triage(e)
        if v.verdict != "likely safe":
            continue
        missed += 1
        top = e.auth_results[0].lower() if e.auth_results else ""
        stats["auth_present"]["yes" if top else "no"] += 1
        for k in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{k}=(\w+)", top)
            stats[k][m.group(1) if m else "(absent)"] += 1
        n = len(e.links)
        stats["links"]["0" if n == 0 else "1-3" if n <= 3 else "4-10" if n <= 10 else "11+"] += 1
        for t in {tld(l.host) for l in e.links if l.host}:
            stats["link_tlds"][t] += 1
        stats["from_tld"][tld(e.from_domain)] += 1
        text = f"{e.subject} {e.text} {e.html}".lower()
        lang = max(LANG_HINTS, key=lambda k: sum(text.count(w) for w in LANG_HINTS[k]))
        stats["language"][lang if any(text.count(w) for w in LANG_HINTS[lang]) else "unclear"] += 1
        stats["has_html"]["yes" if e.html else "no"] += 1
        for a in e.attachments:
            stats["attachment_ext"][a.rsplit(".", 1)[-1].lower() if "." in a else "(none)"] += 1
        stats["score"][str(v.score)] += 1
        for w in set(re.findall(r"[a-zà-ú]{4,}", e.subject.lower())):
            stats["subject_words"][w] += 1
        same = bool(e.links) and all(registrable(l.host) == registrable(e.from_domain) for l in e.links if l.host)
        stats["auth_trust"]["links all on sender's own domain" if same else "links elsewhere / none"] += 1

    print(f"Missed phishing emails: {missed}")
    for name, c in stats.items():
        top = c.most_common(25 if name == "subject_words" else 12)
        print(f"\n{name}: " + ", ".join(f"{k}={v}" for k, v in top))


if __name__ == "__main__":
    main()
