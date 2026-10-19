<!--
Pull request template snippet for continuous threat modeling (guide Section 14.4).
Copy into .github/pull_request_template.md in your own repository.
-->

### Security design check

- [ ] Does this change add or modify an entry point, trust boundary, data store, or external dependency?
- [ ] Does it change authentication, authorization, session, or crypto behavior?
- [ ] Does it introduce or move sensitive data (PII, credentials, payment data)?
- [ ] If any box is checked: threat model updated in `threat-model/` (link the diff) or security reviewer tagged.
