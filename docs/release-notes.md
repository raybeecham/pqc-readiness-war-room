# Release Notes

## v0.7 - Target Comparison Mode

This release adds side-by-side comparison for public HTTPS posture signals while
keeping the tool stateless and bounded.

### Added

- optional `compare` query parameter
- comparison of the primary target plus up to three additional public hostnames
- side-by-side rows for HTTPS reachability, HTTP status, HSTS, HTTP/3
  advertisement through `Alt-Svc`, CSP, limited assessment status, and posture
  score
- comparison input in the existing assessment form

### Maintained Boundaries

- no storage
- no uploads
- no databases
- no third-party APIs
- no PQC verification claim
- no TLS key exchange group enumeration

### Example

```text
?target=github.com&compare=cloudflare.com,nist.gov,nsa.gov
```

## v0.6.1 - Evidence Confidence Polish

This patch tightens Evidence Ledger wording so missing target header signals are
classified as `Not observed` instead of implying that the signal itself was
observed.

### Changed

- absent target HTTP/3 advertisement rows now show confidence `Not observed`
- absent target HSTS rows now show confidence `Not observed`
- response status rows still show `Observed` when a target response was
  received

## v0.6 - Evidence Ledger

This release adds source transparency to the dashboard without expanding the
tool into a scanner.

### Added

- Evidence Ledger dashboard card
- source mapping for browser-to-edge metadata
- source mapping for target fetch and response header signals
- derived posture model rows for TLS modernization and PQC migration readiness
- explicit unknown, not verified, and not assessed rows for PQC and
  crypto-agility gaps

### Maintained Boundaries

- no PQC verification claim
- no ML-KEM or hybrid PQC proof
- no ECH proof
- no TLS key exchange group enumeration
- no crypto inventory scan
- no uploads, databases, storage bindings, or external APIs

### Key Takeaway

Every visible claim should be traceable to an observed source, a derived model
output, or an explicit unknown.

## v0.5 - Validation Narrative

This release turns the dashboard into a clearer posture narrative while keeping
the evidence boundaries explicit.

### Added

- Executive Summary narrative
- executive summary cards for TLS modernization, PQC verification, migration
  readiness, and crypto-agility status
- Protocol Intelligence
- PQC Migration Readiness analysis
- Crypto Discovery evidence model
- Validation Plan
- limited target assessment warning in the Executive Summary

### Maintained Boundaries

- no PQC verification claim
- no TLS key exchange group enumeration claim
- no uploads
- no databases
- no external APIs
- no CAMM questionnaire

### Known Limitations

- posture model only
- browser-to-edge metadata only
- target assessments can be limited by denial, challenge, rate limits, or
  intermediary responses
- crypto discovery is not assessed
- crypto-agility is not assessed
- ML-KEM, hybrid PQC, ECH, full inventory, and organizational agility remain
  unknown

### Recommended Demo Path

- start with the Executive Summary
- run a target assessment against `github.com` or `nsa.gov`
- explain observed versus unknown signals
- show Protocol Intelligence and Crypto Discovery
- close with the Validation Plan and Executive Takeaway

### Key Takeaway

A modern TLS posture is a prerequisite for PQC migration, but it is not proof of
PQC readiness.
