# PQC Readiness War Room

Edge-based assessment tool for explaining TLS modernization, HTTPS posture,
protocol visibility, and crypto-agility readiness gaps without overstating
post-quantum cryptography readiness.

## Live Demo

https://pqc-readiness-war-room.raybeecham2009.workers.dev

## Project Overview

PQC Readiness War Room runs as a Cloudflare Worker. It evaluates:

- TLS modernization posture
- HTTPS security posture
- Protocol visibility indicators
- Crypto-agility readiness gaps

The platform intentionally separates observed signals from unknown signals.
That separation is the core point of the tool: a modern TLS or HTTPS posture is
useful evidence, but it is not proof of PQC readiness.

## What The Tool Does

For the browser-to-edge request, the Worker observes Cloudflare request
metadata such as:

- HTTP protocol
- TLS version
- TLS cipher
- Cloudflare edge colo
- coarse network and location context

For an optional public target domain, the Worker performs a lightweight HTTPS
posture assessment and observes selected response metadata such as:

- HTTPS reachability
- final URL and HTTP status
- `Alt-Svc`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Server`
- `CF-Cache-Status`

The result is a posture model, not a definitive cryptographic inventory.

## Observed Signals

Observed signals are facts the Worker can see directly from the current request
or from a target HTTPS response.

Examples:

- HTTPS endpoint reachable
- HTTPS final URL
- HTTP/2 or HTTP/3 observed
- TLS 1.3 observed on the browser-to-edge connection
- AEAD-like cipher observed on the browser-to-edge connection
- HSTS observed
- HTTP/3 advertised through `Alt-Svc`
- selected security headers observed

## Unknown Signals

Unknown signals are intentionally not treated as proven. This avoids turning a
demo into a false readiness claim.

Examples:

- ML-KEM support
- hybrid PQC key exchange support
- ECH support
- certificate agility
- cryptographic inventory coverage
- vendor PQC migration roadmap
- organizational crypto-agility

## What It Can Prove

- TLS modernization indicators
- HTTP protocol posture
- HTTPS reachability
- security header observations
- browser-to-edge metadata
- whether selected target response headers were observed

## What It Cannot Prove

- ML-KEM support
- hybrid PQC support
- ECH support
- complete crypto inventory coverage
- certificate lifecycle agility
- vendor readiness
- organizational crypto-agility
- full PQC migration readiness

## Current Implementation

The current Worker provides:

- TLS Modernization Score
- PQC Readiness model
- Crypto-Agility Score placeholder
- target HTTPS posture assessment
- observed browser-to-edge connection metadata
- Protocol Intelligence
- modernization findings
- recommendation text
- platform roadmap
- explicit "cannot prove alone" section

The scoring is intentionally conservative. For example, observing HTTP/3 or TLS
1.3 increases modernization confidence, but PQC support remains unverified.

## Configuration Source Of Truth

This repository treats the local Wrangler project as the source of truth for the
Cloudflare Worker.

Cloudflare's Wrangler documentation recommends treating the Wrangler
configuration file as the source of truth for Worker configuration when using
Wrangler, and avoiding dashboard edits that drift from the local project:
https://developers.cloudflare.com/workers/wrangler/configuration/

In this repo:

- Worker configuration: `worker/wrangler.toml`
- Worker entry point: `worker/src/index.js`
- package scripts: `worker/package.json`

Deployments should be made from the local project with Wrangler so code,
configuration, and documentation stay aligned.

## Local Development

From the `worker` directory:

```sh
npm install
npm run dev
```

Deploy:

```sh
npm run deploy
```

## Protocol Intelligence

The dashboard includes a Protocol Intelligence card. It uses the observed
browser-to-edge HTTP protocol to explain visibility implications without adding
forms, uploads, storage, questionnaires, or external APIs.

Example output:

```text
Protocol Intelligence

Observed HTTP: HTTP/3

Why It Matters
--------------
QUIC transport reduces traditional
TCP-centric inspection assumptions.

Operational Impact
------------------
Network visibility shifts toward:
- edge telemetry
- endpoint telemetry
- application telemetry
```

This connects directly to:

- the TLS presentation narrative
- the Cloudflare demo
- the PQC readiness story
- visibility planning for modern transport protocols

## PQC Readiness Analysis

The tool should not guess PQC readiness. The next analysis layer should examine
observable modernization signals and then clearly state what remains unknown.

Inputs to analyze:

- `Alt-Svc`
- HTTP/3
- TLS modernization
- HTTPS reachability
- security headers
- server posture

Output:

```text
PQC Migration Readiness: LOW | MEDIUM | HIGH

Reasoning:
- observed signals
- missing signals
- unknown signals
- recommended validation steps
```

The readiness label should describe migration preparedness, not verified PQC
support.

## Roadmap

v0.1:

- TLS Modernization
- HTTPS Posture
- Crypto Agility Model

v0.2:

- Protocol Intelligence

v0.3:

- PQC Readiness Analysis

v0.4:

- Crypto Discovery

v0.5:

- CAMM Assessment

## Bigger Picture

PQC Readiness War Room is meant to support a practical readiness narrative:

- modern TLS is necessary, but not sufficient
- HTTP/3 changes visibility assumptions
- edge telemetry can explain what was actually observed
- unknowns must remain explicit until validated by scanning, inventory, vendor
  evidence, or governance review

That makes the project a natural foundation for PQC, crypto discovery, and
federal crypto-agility work.
