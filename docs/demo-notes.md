# Demo Notes

## 2-Minute Demo Flow

1. Open the live dashboard or run the Worker locally with Wrangler.

2. Start with the Executive Summary.

   Use it to frame the whole demo: transport posture, PQC verification status,
   migration readiness, limited target assessment status if present, and the
   next validation action.

3. Show the browser-to-edge TLS modernization score.

   Explain that the Worker observes browser-to-edge metadata such as TLS
   version, HTTP protocol, cipher, and edge context.

4. Run a target HTTPS posture assessment against `github.com`.

   Use the target input to show HTTPS reachability, response status, selected
   security headers, and `Alt-Svc` if observed.

5. Run Target Comparison Mode.

   Use `github.com` as the primary target and compare it with
   `cloudflare.com,nist.gov,nsa.gov`. Explain that the comparison shows public
   HTTPS posture differences only. It does not store results, verify PQC
   support, or enumerate TLS key exchange groups.

6. Explain observed vs unknown signals.

   Observed signals are things the Worker can see directly. Unknown signals are
   deliberately not treated as proven. The tool does not prove ML-KEM, hybrid
   PQC, ECH, complete crypto inventory, or organizational crypto-agility.

7. Show the Evidence Ledger.

   Use it to show where each claim came from: Worker request metadata, target
   fetch results, response headers, derived model outputs, or intentionally
   unknown/not verified signals.

8. Show PQC Migration Readiness.

   Explain that LOW, MEDIUM, or HIGH describes migration preparedness from
   observed modernization signals. It does not mean PQC support was verified.
   While Crypto Discovery is NOT ASSESSED, readiness is capped below HIGH even
   when TLS modernization signals are strong.

9. Show Crypto Discovery.

   Explain that discovery is marked NOT ASSESSED. The card lists evidence that
   would be needed before a migration plan can be trusted, while keeping
   internal systems, source code crypto usage, vendor crypto, and data-at-rest
   crypto out of scope for this Worker.

10. Show the Validation Plan.

   Explain that the plan lists next evidence to collect and explicitly says
   what not to infer from the current posture model.

11. Close with the key takeaway.

   "A modern TLS posture is a prerequisite for PQC migration, but it is not proof of PQC readiness."

## Demo Boundary

This is a posture model, not a full cryptographic scanner. It separates
observed signals from unknown signals so the demo does not overstate PQC
readiness.
