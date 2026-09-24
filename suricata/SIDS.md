# SID registry

Every Suricata rule needs a signature ID unique across every ruleset loaded on
the sensor. Collide with one and the later rule silently wins, so local content
is numbered in a range nobody else uses.

## Range

Rules here use **9000000-9999999**, the block reserved for local rules. It sits
clear of the ranges the public rulesets occupy:

| Range | Owner |
| --- | --- |
| 1000000-1999999 | Sigs reserved for local use by convention |
| 2000000-2999999 | Emerging Threats |
| 3000000-3999999 | Suricata community ruleset |
| 9000000-9999999 | Local rules — this repository |

Running ET or the community ruleset alongside this one is therefore safe: no
SID in this repository can shadow a rule from either.

## Allocation

| SID | Category | File |
| --- | --- | --- |
| 9000001 | scan | [`rules/scan/ssh-bruteforce.rules`](rules/scan/ssh-bruteforce.rules) |

**Next available SID: 9000002**

Claim a SID by taking the next available number, adding a row above, and
bumping the line. A SID is never reused once allocated, even if its rule is
retired — the number stays spent so old alerts in a SIEM remain unambiguous.
