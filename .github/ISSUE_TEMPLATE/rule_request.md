---
name: New Detection Rule Proposal
about: Suggest a new security rule, secret pattern, or prompt-injection check
title: "[rule] "
labels: enhancement, security
---

## Proposed Rule

- **Suggested Rule ID:** (e.g. `exec.*`, `path.*`, `secret.*`, `injection.*`)
- **Direction:** `client -> server` or `server -> client`
- **Suggested Severity:** `low` | `medium` | `high` | `critical`

## Threat Description

<!-- What attack, leak, or footgun does this rule prevent? -->

## Example Payloads

### Should Trigger (Positive Cases)
```json
{}
```

### Should NOT Trigger (Benign Negative Cases)
```json
{}
```
