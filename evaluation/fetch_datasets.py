"""Download the evaluation data into evaluation/data/ (git-ignored: the emails are never committed).

- Phishing: a fixed random sample from rf-peixoto/phishing_pot (CC BY-NC 4.0), pinned to one commit.
- Legitimate: SpamAssassin public corpus "easy_ham" (2003), published for testing spam filters.
"""
import http.client
import io
import json
import random
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
PHISHING_REPO = "rf-peixoto/phishing_pot"
PHISHING_COMMIT = "2933c0341b12"  # resolved to the full SHA at fetch time and recorded in manifest.json
SAMPLE_SIZE = 300
SEED = 2026
HAM_URL = "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
UA = {"User-Agent": "phish-triage evaluation (github.com/Ezashi9/phish-triage)"}


def get(url: str, attempts: int = 4) -> bytes:
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
                return r.read()
        except (http.client.IncompleteRead, urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == attempts:
                raise
            time.sleep(2 * attempt)


def fetch_phishing() -> dict:
    commit = json.loads(get(f"https://api.github.com/repos/{PHISHING_REPO}/commits/{PHISHING_COMMIT}"))["sha"]
    tree = json.loads(get(f"https://api.github.com/repos/{PHISHING_REPO}/git/trees/{commit}?recursive=1"))
    names = sorted(t["path"] for t in tree["tree"] if t["path"].startswith("email/") and t["path"].endswith(".eml"))
    sample = sorted(random.Random(SEED).sample(names, min(SAMPLE_SIZE, len(names))))
    out = DATA / "phishing"
    out.mkdir(parents=True, exist_ok=True)
    for i, path in enumerate(sample, 1):
        target = out / Path(path).name
        if not target.exists():
            target.write_bytes(get(f"https://raw.githubusercontent.com/{PHISHING_REPO}/{commit}/{path}"))
        if i % 50 == 0:
            print(f"  phishing {i}/{len(sample)}")
    return {"repo": PHISHING_REPO, "commit": commit, "total_in_repo": len(names), "sample": len(sample), "seed": SEED,
            "truncated_tree": tree.get("truncated", False)}


def fetch_ham() -> dict:
    out = DATA / "legitimate"
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(get(HAM_URL)), mode="r:bz2") as tar:
        members = [m for m in tar.getmembers() if m.isfile() and not m.name.endswith("cmds")]
        for m in members:
            (out / (Path(m.name).name.replace(".", "_") + ".eml")).write_bytes(tar.extractfile(m).read())
    return {"source": HAM_URL, "messages": len(members)}


if __name__ == "__main__":
    manifest = {"phishing": fetch_phishing(), "legitimate": fetch_ham()}
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
