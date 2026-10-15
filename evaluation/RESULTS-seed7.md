# Evaluation results (phishing sample seed 7)

Phishing sample: 300 emails drawn at random (seed 7) from 12271 in [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) at commit `2933c0341b12`.  
Legitimate sample: 2500 emails from the SpamAssassin public corpus (easy_ham, 2003).

| | Phishing emails | Legitimate emails |
|---|---|---|
| Analysed | 300 | 2500 |
| Could not parse | 0 | 0 |
| Verdict: phishing | 90 (30.0%) | 1 (0.0%) |
| Verdict: suspicious | 88 (29.3%) | 21 (0.8%) |
| Verdict: likely safe | 122 (40.7%) | 2478 (99.1%) |

**Caught (phishing or suspicious): 59.3% of phishing emails.**  
**False alarms (legitimate flagged phishing or suspicious): 0.9%.**

## Which checks fired

| Check | Phishing emails | Legitimate emails |
|---|---|---|
| auth | 57.3% | 0.0% |
| sender | 38.3% | 63.7% |
| lure | 32.7% | 0.4% |
| links | 27.3% | 0.6% |
| language | 27.0% | 0.3% |
| impersonation | 24.7% | 5.6% |
| lookalike | 19.7% | 0.3% |
| tld | 7.0% | 0.0% |
