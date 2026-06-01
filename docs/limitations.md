# Limitations

PQC Readiness War Room is a posture model, not a full cryptographic scanner.

## What The Worker Can Observe

- Browser-to-edge TLS metadata exposed in the Worker request context
- Browser-to-edge HTTP protocol
- HTTPS reachability for a public target domain
- selected target response headers
- `Alt-Svc` advertisements
- security header presence

## What The Worker Cannot Prove

- ML-KEM support
- hybrid PQC key exchange support
- ECH support
- complete TLS key exchange group coverage
- complete certificate lifecycle agility
- complete cryptographic inventory
- vendor PQC readiness
- organizational crypto-agility

## Analysis Boundary

The PQC Migration Readiness label describes migration preparedness from
observable modernization signals. It does not verify post-quantum cryptography
support.

Use the tool to explain observed signals, unknown signals, and next-step
validation needs. Do not use it as a replacement for active cryptographic
scanning, endpoint inventory, vendor evidence, architecture review, or
governance assessment.
