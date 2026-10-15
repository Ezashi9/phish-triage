# Phish Triage

[![Tests](https://github.com/Ezashi9/phish-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezashi9/phish-triage/actions/workflows/ci.yml)

Triages a suspicious email (`.eml`) the way a junior SOC analyst would: checks whether the sender is genuine, whether the links go where they claim, and whether the attachments are dangerous, then gives a verdict with the reasons.

**It never opens a link, runs an attachment or contacts anything mentioned in the email.** It only reads the text, and the indicators it reports are "defanged" (`hxxp://evil[.]com`) so they can't be clicked by accident.

## Results on real emails

Evaluation in progress. See [evaluation/RESULTS.md](evaluation/RESULTS.md) once the run completes.
