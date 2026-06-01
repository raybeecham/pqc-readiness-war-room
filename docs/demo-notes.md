# Demo Notes

## 2-Minute Demo Flow

1. Open the live dashboard or run the Worker locally with Wrangler.

2. Show the browser-to-edge TLS modernization score.

   Explain that the Worker observes browser-to-edge metadata such as TLS
   version, HTTP protocol, cipher, and edge context.

3. Run a target HTTPS posture assessment against `github.com`.

   Use the target input to show HTTPS reachability, response status, selected
   security headers, and `Alt-Svc` if observed.

4. Explain observed vs unknown signals.

   Observed signals are things the Worker can see directly. Unknown signals are
   deliberately not treated as proven. The tool does not prove ML-KEM, hybrid
   PQC, ECH, complete crypto inventory, or organizational crypto-agility.

5. Show PQC Migration Readiness.

   Explain that LOW, MEDIUM, or HIGH describes migration preparedness from
   observed modernization signals. It does not mean PQC support was verified.

6. Show Crypto Discovery.

   Explain that discovery is marked NOT ASSESSED. The card lists evidence that
   would be needed before a migration plan can be trusted, while keeping
   internal systems, source code crypto usage, vendor crypto, and data-at-rest
   crypto out of scope for this Worker.

7. Close with the key takeaway.

   "A modern TLS posture is a prerequisite for PQC migration, but it is not proof of PQC readiness."

## Demo Boundary

This is a posture model, not a full cryptographic scanner. It separates
observed signals from unknown signals so the demo does not overstate PQC
readiness.
