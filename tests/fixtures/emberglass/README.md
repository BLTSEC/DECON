# Operation Emberglass — synthetic engagement notes

Vendored from [offsec-demo-vault](https://github.com/BLTSEC/offsec-demo-vault)
(`vault/Engagements/Operation Emberglass/`) so DECON's test suite stays
self-contained.

**Everything here is fictional.** Names, organizations, domains, IP addresses,
credentials, hashes, tokens, and findings were written for demonstration and do
not describe a real person or engagement. The credential-shaped strings are
nonfunctional test data.

`expectations.json` is the contract the upstream demo harness asserts against:

- `must_remove` — values that must not survive redaction
- `must_preserve` — analytical content that must survive, so redaction stays
  useful rather than merely destructive
- `repeated_values` — values that appear more than once and must therefore map
  to a consistent placeholder

These notes are the regression corpus for two real bugs found against them:
an over-greedy SPN match that leaked passwords out of impacket target strings,
and passwords stated in prose that no rule anchored on.
