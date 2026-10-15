# Evaluation results (phishing sample seed 2026)

Phishing sample: 300 emails drawn at random (seed 2026) from 12271 in [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) at commit `2933c0341b12`.  
Legitimate sample: 2500 emails from the SpamAssassin public corpus (easy_ham, 2003).

| | Phishing emails | Legitimate emails |
|---|---|---|
| Analysed | 300 | 2500 |
| Could not parse | 0 | 0 |
| Verdict: phishing | 94 (31.3%) | 3 (0.1%) |
| Verdict: suspicious | 90 (30.0%) | 49 (2.0%) |
| Verdict: likely safe | 116 (38.7%) | 2448 (97.9%) |

**Caught (phishing or suspicious): 61.3% of phishing emails.**  
**False alarms (legitimate flagged phishing or suspicious): 2.1%.**

## Which checks fired

| Check | Phishing emails | Legitimate emails |
|---|---|---|
| auth | 47.7% | 0.0% |
| sender | 40.3% | 63.7% |
| lure | 32.7% | 1.4% |
| impersonation | 29.7% | 5.6% |
| links | 25.3% | 0.6% |
| language | 21.0% | 0.3% |
| lookalike | 17.7% | 0.3% |
| tld | 12.0% | 0.0% |
| attachment | 0.3% | 0.0% |
