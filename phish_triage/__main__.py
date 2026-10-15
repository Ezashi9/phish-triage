import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .checks import defang
from .parse import parse_file
from .triage import triage


def describe(path: Path, v) -> str:
    lines = [f"{path.name}: {v.verdict.upper()} (score {v.score})"]
    lines += [f"  {f.points:+4d}  {f.reason}" for f in v.findings]
    if v.iocs["sender_ips"]:
        lines.append(f"  sender IPs: {', '.join(v.iocs['sender_ips'])}")
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(prog="phish_triage",
                                description="Triage suspicious emails (.eml). Never opens links or attachments.")
    p.add_argument("path", help="an .eml file or a folder of them")
    p.add_argument("--json", help="write full results (including defanged indicators) to this file")
    p.add_argument("--ips", help="write sender IPs from flagged emails to this file, for IOC Enricher")
    args = p.parse_args()

    target = Path(args.path)
    files = sorted(target.glob("*.eml")) if target.is_dir() else [target]
    if not files:
        sys.exit("No .eml files found.")

    results, counts, flagged_ips = [], Counter(), set()
    for f in files:
        try:
            v = triage(parse_file(f))
        except Exception as e:  # one broken file shouldn't stop a batch
            print(f"{f.name}: could not parse ({e})")
            counts["unparseable"] += 1
            continue
        counts[v.verdict] += 1
        if v.verdict != "likely safe":
            flagged_ips.update(v.iocs["sender_ips"])
        results.append({"file": f.name, "verdict": v.verdict, "score": v.score,
                        "findings": [vars(x) for x in v.findings], "iocs": v.iocs})
        if len(files) <= 20:
            print(describe(f, v) + "\n")

    if len(files) > 1:
        print(", ".join(f"{n} {k}" for k, n in counts.most_common()) + f" (of {len(files)} emails)")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    if args.ips:
        Path(args.ips).write_text("\n".join(sorted(flagged_ips)) + "\n", encoding="utf-8")
        print(f"Wrote {len(flagged_ips)} sender IPs to {args.ips} (check them with IOC Enricher)")


if __name__ == "__main__":
    main()
