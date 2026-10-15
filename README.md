# Phish Triage

[![Tests](https://github.com/Ezashi9/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezashi9/phish-triage/actions/workflows/ci.yml)

Triages a suspicious email (`.eml`) the way a junior SOC analyst would: is the sender genuine, do the links go where they claim, are the attachments dangerous, is it pretending to be a brand? It gives a verdict (**phishing**, **suspicious** or **likely safe**) and lists every reason.

**It never opens a link, runs an attachment or contacts anything mentioned in the email.** It only reads the text. The indicators it reports are "defanged" (`hxxp://evil[.]com`) so nobody can click them by accident.

## Results on real emails

Tested on real phishing caught by honeypots ([phishing_pot](https://github.com/rf-peixoto/phishing_pot), 12,271 emails) and real legitimate email (SpamAssassin public corpus, 2,500 emails):

| Version | Phishing caught | False alarms on legitimate email |
|---|---|---|
| First version | 40.3% | 0.7% |
| After improvements (tuning sample) | 54.3% | 0.9% |
| **Final, on a fresh sample it had never seen** | **59.3%** | **0.9%** |

"Caught" means rated phishing or suspicious. Full tables: [held-out results](evaluation/RESULTS-seed7.md), [tuning results](evaluation/RESULTS-seed2026.md), [first version](evaluation/RESULTS-seed2026-v1.md).

### How I tested it without fooling myself

- **Separate tuning and test samples.** I improved the tool using one random sample of 300 phishing emails, then measured it on a *different* random sample. Scoring well only on the sample you tuned on is overfitting. The fresh-sample result (59.3%) matching the tuning result (54.3%) shows the rules generalise.
- **False alarms count as much as catches.** One round of changes raised the catch rate to 61.3% but tripled false alarms to 2.1%. I traced it to a single check and fixed it rather than keeping the bigger headline number. A tool that cries wolf gets ignored.
- **Reproducible.** The samples are drawn with fixed seeds from a pinned dataset commit, so anyone can rerun the exact test.

### What the misses taught me

I added a step that describes the phishing the tool missed, using totals only:

1. **Most missed phishing *passed* email authentication.** SPF passed for 128 of 178 misses and DMARC for nearly 100. Attackers send from domains they own, so SPF, DKIM and DMARC correctly prove *who sent it*, which isn't the same as whether the sender is honest. My first version even gave a DMARC pass a bonus, which helped phishing slip through. I removed it.
2. **37 misses had a From header my parser couldn't read**, so every sender check was skipped. Added a fallback.
3. **Brands were impersonated in the body**, not just the display name: fake McAfee and Norton renewals, crypto wallets.
4. **Scam lures** (casino "free spins", prizes, crypto airdrops), **heavily abused domain endings** (`.icu`, `.site`, `.fit`...) and **non-English phishing** (German, Portuguese) weren't covered.

**Honest limits:** about 4 in 10 phishing emails still look clean to static rules. Many are well-made emails from attacker-owned domains with valid authentication and nothing obviously wrong in the text. Catching those takes URL and domain reputation, sandboxing and user reporting, which is why real organisations layer defences rather than relying on one filter. The legitimate test set is from 2003, so it predates SPF/DKIM/DMARC; the authentication checks have only been tested for false alarms on hand-made emails.

## What it checks

| Check | Examples | Why |
|---|---|---|
| **Authentication** | SPF, DKIM, DMARC failures | Proves the email didn't come from the domain it claims. Only the **topmost** `Authentication-Results` header is trusted: lower ones can be forged by the sender. Passing gives **no** credit (see above). |
| **Sender** | Display name hiding another address (`"security@bank.com" <x@evil>`), Reply-To going to a different domain | Classic business email compromise tricks |
| **Impersonation** | "PayPal" in the display name, subject or link text, but nothing in the email belongs to PayPal | The core of most phishing |
| **Lookalike domains** | `paypa1.com`, `paypal-secure-login.example`, punycode (`xn--`) domains | Domains built to fool a quick glance |
| **Links** | Link text says one domain but goes to another; links to raw IP addresses; URL shorteners; `user@host` tricks; `javascript:` links | Hides where a click really goes |
| **Attachments** | `invoice.pdf.exe`, HTML attachments (fake login pages), macro Office files, ISO/ZIP containers | Malware and credential theft delivery |
| **Language** | Urgency and account threats in English, German, Portuguese and Spanish | Pressure is how phishing gets clicks |
| **Lures** | Free spins, prizes, expired antivirus, crypto airdrops | Common scam themes |
| **Abused TLDs** | `.icu`, `.top`, `.xyz`, `.site`... | Domain endings repeatedly listed by abuse researchers as heavily used for spam and phishing |

Score of 50+ is **phishing**, 25–49 **suspicious**, under 25 **likely safe**.

## Usage

Python 3.10+, standard library only.

```bash
python -m phish_triage suspicious.eml
python -m phish_triage inbox_export/ --json results.json --ips sender_ips.txt
```

`--ips` writes the sending servers' IP addresses from flagged emails, ready to check with [IOC Enricher](https://github.com/Ezashi9/ioc-enricher).

Example output (a hand-made test email; all domains and IPs are documentation-only):

```
demo.eml: PHISHING (score 140)
   +30  DMARC failed: the sender domain's own policy says this message isn't genuine
   +30  Display name mentions 'paypal' but the message comes from account-alerts.example
   +25  Link text shows 'www.paypal.com' but actually goes to 198[.]51[.]100[.]7
   +20  A link points straight at an IP address (198[.]51[.]100[.]7) instead of a domain name
   +20  Pressure or credential language (4 pattern(s)), e.g. urgency, account threats, payment requests
   +15  SPF fail: the sending server isn't authorised to send for this domain
```

## Running the evaluation safely

Real phishing samples contain live malicious links. When I tried to download them locally, my antivirus (correctly) blocked the transfers. So the evaluation runs **on GitHub's servers** ([`.github/workflows/evaluate.yml`](.github/workflows/evaluate.yml)): it downloads the samples, scores them, and commits **only the aggregate numbers**. The emails themselves are never stored in this repository, which also respects the dataset's request not to republish personal information found in the samples.

```bash
python -m unittest discover -s tests -t .   # 23 unit tests on hand-made emails (reserved example domains only)
```

## Project layout

```
phish_triage/
  parse.py      .eml -> sender, headers, text, links, attachments (no network access)
  checks.py     each check returns points and a plain-English reason
  triage.py     combines findings into a verdict and defanged indicators
  __main__.py   command line
evaluation/     dataset download, scoring, miss analysis, and the published results
tests/          unit tests
```

## Credits and licences

- Phishing samples: [phishing_pot](https://github.com/rf-peixoto/phishing_pot) by rf-peixoto, CC BY-NC 4.0, used for non-commercial research and not redistributed.
- Legitimate samples: [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/), published for testing spam filters.
- Built with AI assistance (Claude). I make sure I can explain every check and design decision.
