"""Score phish-triage on the downloaded datasets and write evaluation/RESULTS.md (aggregate numbers only)."""
import json
from collections import Counter
from pathlib import Path

from phish_triage.parse import parse_file
from phish_triage.triage import triage

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"


def run(folder: Path) -> tuple[Counter, Counter, list[int], int]:
    verdicts, checks, scores, errors = Counter(), Counter(), [], 0
    for f in sorted(folder.glob("*.eml")):
        try:
            v = triage(parse_file(f))
        except Exception:
            errors += 1
            continue
        verdicts[v.verdict] += 1
        scores.append(v.score)
        for check in {x.check for x in v.findings if x.points > 0}:
            checks[check] += 1
    return verdicts, checks, scores, errors


def pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


def main() -> None:
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    p_v, p_checks, p_scores, p_err = run(DATA / "phishing")
    l_v, l_checks, l_scores, l_err = run(DATA / "legitimate")
    p_total, l_total = sum(p_v.values()), sum(l_v.values())
    caught = p_v["phishing"] + p_v["suspicious"]
    false_alarms = l_v["phishing"] + l_v["suspicious"]

    lines = [
        f"# Evaluation results (phishing sample seed {manifest['phishing']['seed']})",
        "",
        f"Phishing sample: {manifest['phishing']['sample']} emails drawn at random (seed {manifest['phishing']['seed']}) from "
        f"{manifest['phishing']['total_in_repo']} in [{manifest['phishing']['repo']}](https://github.com/{manifest['phishing']['repo']}) "
        f"at commit `{manifest['phishing']['commit'][:12]}`.  ",
        f"Legitimate sample: {manifest['legitimate']['messages']} emails from the SpamAssassin public corpus (easy_ham, 2003).",
        "",
        "| | Phishing emails | Legitimate emails |",
        "|---|---|---|",
        f"| Analysed | {p_total} | {l_total} |",
        f"| Could not parse | {p_err} | {l_err} |",
        f"| Verdict: phishing | {p_v['phishing']} ({pct(p_v['phishing'], p_total)}) | {l_v['phishing']} ({pct(l_v['phishing'], l_total)}) |",
        f"| Verdict: suspicious | {p_v['suspicious']} ({pct(p_v['suspicious'], p_total)}) | {l_v['suspicious']} ({pct(l_v['suspicious'], l_total)}) |",
        f"| Verdict: likely safe | {p_v['likely safe']} ({pct(p_v['likely safe'], p_total)}) | {l_v['likely safe']} ({pct(l_v['likely safe'], l_total)}) |",
        "",
        f"**Caught (phishing or suspicious): {pct(caught, p_total)} of phishing emails.**  ",
        f"**False alarms (legitimate flagged phishing or suspicious): {pct(false_alarms, l_total)}.**",
        "",
        "## Which checks fired",
        "",
        "| Check | Phishing emails | Legitimate emails |",
        "|---|---|---|",
    ]
    for check in sorted(set(p_checks) | set(l_checks), key=lambda c: -p_checks[c]):
        lines.append(f"| {check} | {pct(p_checks[check], p_total)} | {pct(l_checks[check], l_total)} |")
    (HERE / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (HERE / "results.json").write_text(json.dumps({
        "phishing": {"verdicts": p_v, "checks": p_checks, "errors": p_err, "total": p_total},
        "legitimate": {"verdicts": l_v, "checks": l_checks, "errors": l_err, "total": l_total},
        "manifest": manifest,
    }, indent=2), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
