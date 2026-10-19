## What changed and why

<!-- One topic per pull request. -->

## Checklist

- [ ] New threats, mappings or claims cite a public source (CWE, CAPEC, ATT&CK, standard, or published research)
- [ ] Examples are fictional; no real architectures, credentials, or unpatched vulnerabilities
- [ ] `python3 -m pytest tools/tests -q` passes
- [ ] `python3 tools/validate_threats.py $(git ls-files '*threats.yaml')` passes
- [ ] If `examples/*/threats.yaml` changed, the CSV export was regenerated
