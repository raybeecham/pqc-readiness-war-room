# Limitations

PQC Readiness War Room is a posture model, not a full cryptographic scanner.

## What The Worker Can Observe

- Browser-to-edge TLS metadata exposed in the Worker request context
- Browser-to-edge HTTP protocol
- HTTPS reachability for a public target domain
- selected target response headers
- `Alt-Svc` advertisements
- security header presence
- discovery evidence requirements

## What The Worker Cannot Prove

- ML-KEM support
- hybrid PQC key exchange support
- ECH support
- complete TLS key exchange group coverage
- complete certificate lifecycle agility
- complete cryptographic inventory
- vendor PQC readiness
- organizational crypto-agility
- source code crypto usage
- embedded key or certificate usage
- data-at-rest cryptography coverage
- internal system crypto dependencies

## Analysis Boundary

The PQC Migration Readiness label describes migration preparedness from
observable modernization signals. It does not verify post-quantum cryptography
support.

Readiness is capped below `HIGH` while Crypto Discovery is `NOT ASSESSED`.
This keeps strong TLS modernization from being mistaken for enterprise
migration readiness.

The Crypto Discovery card is an evidence model. It lists required evidence,
current tool coverage, and out-of-scope areas. It does not perform discovery
against uploaded files, internal systems, repositories, databases, or vendor
products.

The Validation Plan is operational guidance for evidence collection. It does
not verify that the evidence exists and does not change unknown signals into
observed signals.

The Evidence Ledger improves traceability by mapping signals to sources and
classifications. It does not add scanner capability, perform inventory, verify
PQC support, or prove organizational crypto-agility.

Target Comparison Mode compares public HTTPS posture signals for a small set of
user-supplied hostnames. It does not store results, compare private systems,
verify PQC support, or enumerate TLS key exchange groups.

Executive Brief Mode summarizes existing dashboard signals for presentation and
screenshot use. It does not add new evidence, call AI services, store results,
generate PDFs, verify PQC support, or replace the Evidence Ledger.

Print / Report View is implemented with browser print CSS. It does not create a
server-side PDF, persist reports, sign reports, or provide an auditable export
workflow.

Use the tool to explain observed signals, unknown signals, and next-step
validation needs. Do not use it as a replacement for active cryptographic
scanning, endpoint inventory, vendor evidence, architecture review, or
governance assessment.
