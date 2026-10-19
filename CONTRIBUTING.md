# Contributing

Contributions that make this guide more accurate, more practical, or more inclusive of other domains are welcome.

## How to contribute

1. Fork the repository and create a branch (`feature/<topic>`).
2. Keep changes focused: one topic per pull request.
3. For new threats or mappings, cite a public source (CWE, CAPEC, ATT&CK, standards, or published research).
4. For new domain sections, follow the existing structure: characteristic threats per STRIDE category, then modeling tips.
5. Open a pull request describing what changed and why. The pull request template includes a short checklist.

Ideas especially welcome: additional worked examples (healthcare, ICS, mobile banking, agentic AI), translations, and threat libraries for common platforms.

## Adding a worked example

Create `examples/<name>/` containing at least:

- `README.md` based on [`templates/threat-model-template.md`](templates/threat-model-template.md)
- `threats.yaml` based on [`templates/threats.yaml`](templates/threats.yaml)

Use fictional organizations only. Do not submit real client architectures, unpatched vulnerabilities, or anything covered by an NDA.

## Local checks

```bash
pip install -r tools/requirements.txt
python3 -m pytest tools/tests -q
python3 tools/validate_threats.py $(git ls-files '*threats.yaml') --coverage
```

The same checks run in GitHub Actions on every push and pull request.

## Style

- Plain, precise English. Define a term before using it.
- Keep a strict separation between threat, vulnerability and mitigation.
- Mitigations are specific and testable ("Encrypt DS1 with KMS key X, decrypt restricted to P3"), never "use encryption".
- Diagrams in Mermaid so they render on GitHub and diff cleanly.

## Licensing of contributions

By contributing you agree that documentation is licensed under [CC BY 4.0](LICENSE) and code under the [MIT License](LICENSE-CODE).
