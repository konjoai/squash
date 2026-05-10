# Sample Policies — paste into `squash quick-check`

Five realistic policy snippets to make the demo experience instant.
Drop any of these into `POST /quick-check` (or paste them at
[getsquash.dev/demo](https://getsquash.dev/demo)) to see a pass/fail
clause-coverage badge in under two seconds.

| File | Framework | Expected verdict |
|------|-----------|------------------|
| `01_privacy_policy.txt` | `gdpr` | pass — comprehensive GDPR-style notice |
| `02_terms_of_service.txt` | `general` | warn — a typical SaaS ToS, partial coverage |
| `03_gdpr_dpa.txt` | `gdpr` | pass — Art. 28 data processing agreement |
| `04_ccpa_notice.txt` | `ccpa` | pass — California-resident notice |
| `05_cookie_policy.txt` | `general` | warn — short cookie banner |

All five are synthetic — written for the squash demo. Not legal advice.
