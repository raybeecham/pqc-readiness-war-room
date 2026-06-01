# Release Notes

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
