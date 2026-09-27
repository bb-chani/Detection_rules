# SID registry

Every Suricata rule needs a signature ID unique across every ruleset loaded on
the sensor. Collide with one and the later rule silently wins, so local content
is numbered in a range nobody else uses.

## Range

Rules here use **9000000-9999999**. How that sits against the allocations in
common use:

| Range | Owner |
| --- | --- |
| 1000000-1999999 | Reserved by convention for local/custom rules |
| 2000000-2099999 | Emerging Threats Open |
| 2100000-2103999 | ET forks of the original Snort GPL signatures |
| 2200000-2299999 | Suricata's own engine-event rules |
| 9000000-9999999 | Local rules — this repository (unallocated block) |

The conventional home for local rules is 1000000-1999999. This repository
deliberately sits outside it, in the 9000000+ block, which is not allocated to
anyone. That buys one more layer of separation than the convention does: these
SIDs cannot collide with ET, with the engine-event rules Suricata ships, or
with someone else's local rules numbered the conventional way on the same
sensor.

Allocations are catalogued at [sidallocation.org](https://sidallocation.org/),
the canonical source for who owns which range.

## Allocation

| SID | Category | File |
| --- | --- | --- |
| 9000001 | scan | [`rules/scan/ssh-bruteforce.rules`](rules/scan/ssh-bruteforce.rules) |

**Next available SID: 9000002**

Claim a SID by taking the next available number, adding a row above, and
bumping the line. A SID is never reused once allocated, even if its rule is
retired — the number stays spent so old alerts in a SIEM remain unambiguous.
