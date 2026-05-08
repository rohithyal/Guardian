## Summary
<!-- What does this PR do? One paragraph. -->

## Type of Change
- [ ] 🐛 Bug fix
- [ ] ✨ New feature / tool
- [ ] 🔒 Security improvement
- [ ] 📝 Documentation
- [ ] 🔧 Refactor / tooling
- [ ] 🚨 Breaking change

## Security Checklist
<!-- Guardian-specific checks — required for all PRs -->
- [ ] No secrets, credentials, or API keys committed
- [ ] New code runs through `scan_secrets` locally — no findings
- [ ] If adding a new dependency: checked against OSV (`check_dependencies`)
- [ ] If changing architecture: threat model updated (`generate_threat_model`)
- [ ] Pydantic validation added for all new tool inputs
- [ ] `pytest tests/ -v` passes locally

## What was tested
<!-- Describe test cases added or updated -->

## NIST / OWASP impact
<!-- If this PR closes a security finding, list the control IDs -->
- Controls addressed: (e.g. SI-2, IA-5, A06:2021)
