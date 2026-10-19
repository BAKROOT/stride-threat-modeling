# STRIDE One-Page Cheat Sheet

Print it, pin it, bring it to every design review. Full detail: [the guide](../README.md).

## The four questions

1. **What are we working on?** Draw the DFD with trust boundaries.
2. **What can go wrong?** Walk STRIDE over every element, boundary-crossing flows first.
3. **What are we going to do about it?** Mitigate, eliminate, transfer or accept, with an owner.
4. **Did we do a good enough job?** Coverage matrix, peer review, tests, pentest feedback.

## STRIDE at a glance

| | Threat | Property violated | Ask | First-line controls |
|---|---|---|---|---|
| **S** | Spoofing | Authentication | Is it really who it claims? Proven or asserted? | Phishing-resistant MFA, mTLS, signed tokens and webhooks, strict token validation |
| **T** | Tampering | Integrity | Could it be changed in transit, at rest, in the build? | Validation, parameterized queries, server-side authority, signing, least-privilege write |
| **R** | Repudiation | Non-repudiation | Can we prove who did it, even against the actor? | Structured audit logs with the real principal, WORM storage, hash chains, signatures |
| **I** | Information disclosure | Confidentiality | Could the wrong party see it, or infer it? | Object-level authZ, minimization, encryption, secrets management, generic errors |
| **D** | Denial of service | Availability | Could it be exhausted, slowed, or made too expensive? | Limits and quotas, timeouts, circuit breakers, DDoS protection, immutable backups |
| **E** | Elevation of privilege | Authorization | Could someone do more than allowed, or escape a boundary? | Deny-by-default authZ, least privilege, isolation, check the original caller |

## STRIDE per element

| Element | S | T | R | I | D | E |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| External entity | ✓ | | ✓ | | | |
| Process | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data store | | ✓ | ✓\* | ✓ | ✓ | |
| Data flow | | ✓ | | ✓ | ✓ | |

\* Log and audit stores. The chart is a starting point; write down threats outside it when you find them.

## DFD rules

- Every store is written and read by a process. No store-to-store or entity-to-store arrows.
- Label every flow with what it carries and how it is authenticated.
- No trust boundaries, no threat model. Draw them first.
- Include admin, support, backup, monitoring, CI/CD and break-glass paths.
- Number everything: E1, P1, DS1, F1, TB1.

## Write threats as sentences

> **[Actor]** can **[action]** **[asset/element]** via **[attack vector]**, resulting in **[impact]**.

*"An external attacker can forge PSP webhook calls to P4 because signatures are not verified, resulting in orders marked paid without payment."*

## Rate: Likelihood x Impact (1 to 5 each)

| Risk | Band | Response |
|---|---|---|
| 20 to 25 | Critical | Fix before release; executive visibility |
| 12 to 19 | High | Fix before release, or signed time-bound acceptance |
| 6 to 11 | Medium | Fix within agreed timeframe |
| 1 to 5 | Low | Fix opportunistically or accept with documentation |

## Facilitator reminders

- Hand the pen to the engineers. Ask, do not tell. Use silence.
- STRIDE is a lens, not a taxonomy: if the T-vs-E debate passes one minute, pick one and move on.
- Ask "says who?" at every trust boundary.
- Prefer verifying with the authority ("verify by fetch") over trusting a message.
- Mitigations must be specific and testable, and each needs a verification method.
- End with owners and tickets, not just a list.
