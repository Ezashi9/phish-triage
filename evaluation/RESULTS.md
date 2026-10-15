# Evaluation results

Phishing sample: 300 emails drawn at random (seed 2026) from 12271 in [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) at commit `2933c0341b12`.  
Legitimate sample: 2500 emails from the SpamAssassin public corpus (easy_ham, 2003).

| | Phishing emails | Legitimate emails |
|---|---|---|
| Analysed | 300 | 2500 |
| Could not parse | 0 | 0 |
| Verdict: phishing | 35 (11.7%) | 1 (0.0%) |
| Verdict: suspicious | 86 (28.7%) | 16 (0.6%) |
| Verdict: likely safe | 179 (59.7%) | 2483 (99.3%) |

**Caught (phishing or suspicious): 40.3% of phishing emails.**  
**False alarms (legitimate flagged phishing or suspicious): 0.7%.**

## Which checks fired

| Check | Phishing emails | Legitimate emails |
|---|---|---|
| auth | 47.7% | 0.0% |
| sender | 42.0% | 63.7% |
| links | 25.3% | 0.6% |
| lookalike | 17.3% | 0.3% |
| language | 15.0% | 0.3% |
| impersonation | 2.7% | 0.0% |
| attachment | 0.3% | 0.0% |
