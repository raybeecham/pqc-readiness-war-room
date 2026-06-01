function normalizeTarget(rawTarget) {
  if (!rawTarget) return "";

  let target = rawTarget.trim();

  target = target.replace(/^https?:\/\//i, "");
  target = target.replace(/\/.*$/, "");
  target = target.replace(/:\d+$/, "");

  return target.toLowerCase();
}

function isValidPublicHostname(hostname) {
  if (!hostname) return false;
  if (hostname === "localhost") return false;
  if (hostname.includes("..")) return false;
  if (!/^[a-z0-9.-]+$/i.test(hostname)) return false;
  if (!hostname.includes(".")) return false;

  const blockedPatterns = [
    /^127\./,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^169\.254\./,
    /^0\./,
    /^::1$/,
  ];

  return !blockedPatterns.some((pattern) => pattern.test(hostname));
}

function headerValue(headers, name) {
  return headers.get(name) || "Not observed";
}

function scoreTargetSignals(signals) {
  let score = 0;

  if (signals.reachable) score += 20;
  if (signals.httpsRedirectOrSuccess) score += 20;
  if (signals.hsts !== "Not observed") score += 15;
  if (signals.altSvc.toLowerCase().includes("h3")) score += 15;
  if (signals.csp !== "Not observed") score += 10;
  if (signals.xFrameOptions !== "Not observed") score += 5;
  if (signals.xContentTypeOptions !== "Not observed") score += 5;
  if (signals.referrerPolicy !== "Not observed") score += 5;
  if (signals.permissionsPolicy !== "Not observed") score += 5;

  return Math.min(score, 100);
}

function confidenceFromTarget(signals) {
  if (!signals || !signals.reachable) return "LOW";

  let observed = 0;

  if (signals.hsts !== "Not observed") observed++;
  if (signals.altSvc !== "Not observed") observed++;
  if (signals.csp !== "Not observed") observed++;
  if (signals.xFrameOptions !== "Not observed") observed++;
  if (signals.xContentTypeOptions !== "Not observed") observed++;
  if (signals.referrerPolicy !== "Not observed") observed++;
  if (signals.permissionsPolicy !== "Not observed") observed++;

  if (observed >= 4) return "MEDIUM";
  if (observed >= 2) return "LOW-MEDIUM";
  return "LOW";
}

function signalLine(observed, text) {
  return observed
    ? `<div class="signal observed">✓ ${text}</div>`
    : `<div class="signal missing">✕ ${text}</div>`;
}

function analysisLine(text) {
  return `<div class="checkbox-line">${text}</div>`;
}

function buildPqcMigrationAnalysis({
  tlsIsModern,
  httpIsModern,
  usesHttp3,
  cipherIsAead,
  targetAssessment,
  discoveryAssessed,
}) {
  let score = 0;
  const observed = [];
  const gaps = [];
  const unknowns = [
    "ML-KEM support not proven",
    "Hybrid PQC key exchange support not proven",
    "ECH support not proven",
    "Cryptographic inventory coverage not proven",
    "Organizational crypto-agility not proven",
  ];

  if (tlsIsModern) {
    score += 25;
    observed.push("TLS 1.3 observed on the browser-to-edge connection");
  } else {
    gaps.push("TLS 1.3 was not observed on the browser-to-edge connection");
  }

  if (cipherIsAead) {
    score += 15;
    observed.push("AEAD-like cipher observed on the browser-to-edge connection");
  } else {
    gaps.push("AEAD cipher posture could not be confirmed");
  }

  if (usesHttp3) {
    score += 15;
    observed.push("HTTP/3 observed on the browser-to-edge connection");
  } else if (httpIsModern) {
    score += 10;
    observed.push("Modern HTTP protocol observed on the browser-to-edge connection");
  } else {
    gaps.push("Modern HTTP protocol was not confirmed");
  }

  if (!targetAssessment) {
    gaps.push("No target HTTPS posture assessment has been run");
  } else if (!targetAssessment.reachable) {
    gaps.push("Target HTTPS endpoint was not reachable");
  } else {
    score += 15;
    observed.push("Target HTTPS endpoint reachable");

    if (targetAssessment.httpsRedirectOrSuccess) {
      score += 10;
      observed.push("Target final URL uses HTTPS");
    } else {
      gaps.push("Target final URL did not confirm HTTPS");
    }

    if (targetAssessment.hsts !== "Not observed") {
      score += 5;
      observed.push("HSTS observed on target response");
    } else {
      gaps.push("HSTS was not observed on target response");
    }

    if (targetAssessment.altSvc.toLowerCase().includes("h3")) {
      score += 10;
      observed.push("Target advertises HTTP/3 through Alt-Svc");
    } else {
      gaps.push("Target HTTP/3 support was not observed through Alt-Svc");
    }

    if (targetAssessment.csp !== "Not observed") {
      score += 5;
      observed.push("Content Security Policy observed on target response");
    }

    if (targetAssessment.limited) {
      gaps.push(
        "Target response may be limited by challenge, denial, rate limit, or intermediary behavior",
      );
    }
  }

  score = Math.min(score, 100);

  const cappedByDiscovery = !discoveryAssessed && score >= 75;

  if (cappedByDiscovery) {
    score = 74;
    gaps.push(
      "Crypto discovery evidence has not been assessed, so readiness is capped below HIGH",
    );
  }

  const level = score >= 75 ? "HIGH" : score >= 50 ? "MEDIUM" : "LOW";
  const reasoning =
    cappedByDiscovery
      ? "Strong modernization signals are present, but crypto discovery is not assessed, so readiness is capped below HIGH."
      : level === "HIGH"
      ? "Observed modernization signals suggest a stronger migration foundation, but PQC support remains unverified."
      : level === "MEDIUM"
        ? "Some modernization signals are present, but important target or inventory evidence is still missing."
        : "Observed evidence is too limited to treat the environment as migration-ready.";

  return {
    level,
    score,
    reasoning,
    observed,
    gaps,
    unknowns,
    cappedByDiscovery,
  };
}

export default {
  async fetch(request) {
    const cf = request.cf || {};
    const url = new URL(request.url);

    const rawTarget = url.searchParams.get("target") || "";
    const target = normalizeTarget(rawTarget);

    const protocol = cf.httpProtocol || "Unknown";
    const tlsVersion = cf.tlsVersion || "Unknown";
    const cipher = cf.tlsCipher || "Unknown";
    const colo = cf.colo || "Unknown";
    const country = cf.country || "Unknown";
    const city = cf.city || "Unknown";
    const region = cf.region || "Unknown";
    const asn = cf.asn || "Unknown";
    const asOrg = cf.asOrganization || "Unknown";

    const tlsIsModern = tlsVersion.includes("1.3");
    const httpIsModern = protocol === "HTTP/2" || protocol === "HTTP/3";
    const usesHttp3 = protocol === "HTTP/3";
    const usesHttp2 = protocol === "HTTP/2";

    const cipherIsAead =
      cipher.includes("GCM") ||
      cipher.includes("CHACHA") ||
      cipher.includes("POLY1305") ||
      cipher.includes("AEAD");

    const echStatus = "Unknown from Worker context";
    const pqcVerified = false;

    let tlsModernizationScore = 0;
    const findings = [];

    if (tlsIsModern) {
      tlsModernizationScore += 30;
      findings.push({
        label: "TLS 1.3 observed",
        status: "PASS",
        detail: "The browser-to-edge connection is using TLS 1.3.",
      });
    } else {
      findings.push({
        label: "TLS 1.3 not observed",
        status: "WARN",
        detail: "The Worker did not observe TLS 1.3 for this request.",
      });
    }

    if (httpIsModern) {
      tlsModernizationScore += 15;
      findings.push({
        label: "Modern HTTP protocol observed",
        status: "PASS",
        detail: `${protocol} was observed between browser and edge.`,
      });
    } else {
      findings.push({
        label: "Modern HTTP protocol not confirmed",
        status: "WARN",
        detail: `Observed protocol: ${protocol}.`,
      });
    }

    if (cipherIsAead) {
      tlsModernizationScore += 15;
      findings.push({
        label: "AEAD cipher observed",
        status: "PASS",
        detail:
          "Observed cipher appears to use modern authenticated encryption.",
      });
    } else {
      findings.push({
        label: "AEAD cipher not confirmed",
        status: "WARN",
        detail: `Observed cipher: ${cipher}.`,
      });
    }

    if (
      tlsVersion !== "TLSv1.0" &&
      tlsVersion !== "TLSv1.1" &&
      tlsVersion !== "TLSv1.2"
    ) {
      tlsModernizationScore += 10;
      findings.push({
        label: "No legacy TLS observed",
        status: "PASS",
        detail: "No TLS 1.0, 1.1, or 1.2 signal was observed for this request.",
      });
    } else {
      findings.push({
        label: "Legacy TLS signal observed",
        status: "FAIL",
        detail: "Legacy TLS should be removed or tightly controlled.",
      });
    }

    tlsModernizationScore += 10;
    findings.push({
      label: "ECH planning required",
      status: "INFO",
      detail: "ECH status is not directly provable from this Worker context.",
    });

    findings.push({
      label: "PQC support not directly verified",
      status: "INFO",
      detail: "This Worker cannot prove PQC or hybrid KEM support by itself.",
    });

    let modernizationPosture = "MODERATE";
    if (tlsModernizationScore >= 75) modernizationPosture = "STRONG";
    if (tlsModernizationScore < 55) modernizationPosture = "WEAK";

    const pqcReadinessLevel = pqcVerified ? "VERIFIED" : "NOT VERIFIED";
    const pqcReadinessScore = pqcVerified ? 80 : 0;

    const cryptoAgilityStatus = "NOT ASSESSED";
    const cryptoDiscovery = {
      status: "NOT ASSESSED",
      requiredEvidence: [
        "TLS endpoint inventory",
        "certificate inventory",
        "application crypto dependencies",
        "vendor crypto dependencies",
        "code and library crypto usage",
        "data-at-rest encryption dependencies",
        "key and certificate ownership",
      ],
      currentCoverage: [
        "browser-to-edge TLS metadata",
        "HTTPS posture signals for a public target",
        "selected response headers",
        "Alt-Svc advertisements",
      ],
      notCovered: [
        "internal systems",
        "source code crypto usage",
        "embedded keys or certificates",
        "vendor product crypto",
        "data-at-rest crypto",
        "complete key ownership and rotation evidence",
      ],
    };
    const validationPlan = {
      priorityOne: [
        "Confirm TLS endpoint inventory",
        "Validate certificate inventory",
        "Check vendor PQC roadmap",
      ],
      priorityTwo: [
        "Identify application crypto dependencies",
        "Map visibility requirements for HTTP/3",
        "Define ownership for migration planning",
      ],
      doNotInfer: [
        "ML-KEM support",
        "hybrid PQC support",
        "ECH support",
        "crypto-agility maturity",
      ],
    };

    const visibilityImpact = usesHttp3
      ? "HTTP/3 indicates QUIC-based transport. This can reduce traditional TCP-centric inspection assumptions."
      : usesHttp2
        ? "HTTP/2 over TLS provides a familiar TCP-based enterprise visibility posture."
        : "Protocol visibility is unclear. Validate from browser, proxy, and edge logs.";

    const protocolIntelligence = usesHttp3
      ? {
          protocol: "HTTP/3",
          interpretation: "QUIC-aware posture",
          whyItMatters:
            "QUIC can reduce traditional TCP-centric inspection assumptions.",
          guidanceHeading: "Operational Impact",
          operationalImpact:
            "Visibility shifts toward edge telemetry, endpoint telemetry, application logs, and policy control points.",
          telemetrySources:
            "Edge telemetry, endpoint telemetry, application logs, policy control points.",
        }
      : usesHttp2
        ? {
            protocol: "HTTP/2",
            interpretation: "TCP-based encrypted transport",
            whyItMatters:
              "HTTP/2 remains easier to reason about with traditional TCP-centric network tooling, but payload remains encrypted.",
            guidanceHeading: "Operational Impact",
            operationalImpact:
              "Use flow metadata, endpoint telemetry, application logs, and authorized inspection where justified.",
            telemetrySources:
              "Flow metadata, endpoint telemetry, application logs, authorized inspection where justified.",
          }
        : {
            protocol: protocol === "Unknown" ? "Unknown" : protocol,
            interpretation:
              protocol === "Unknown"
                ? "Protocol could not be determined from the Worker context."
                : "Protocol was observed, but it is not HTTP/2 or HTTP/3 in this request context.",
            whyItMatters: visibilityImpact,
            guidanceHeading: "Recommendation",
            operationalImpact:
              "Validate using browser devtools, proxy logs, and edge logs before drawing protocol visibility conclusions.",
            telemetrySources: "Browser devtools, proxy logs, edge logs.",
          };

    let targetAssessment = null;

    if (target) {
      if (!isValidPublicHostname(target)) {
        targetAssessment = {
          target,
          valid: false,
          reachable: false,
          error: "Invalid or non-public hostname.",
          score: 0,
          confidence: "LOW",
        };
      } else {
        const targetUrl = `https://${target}/`;

        try {
          const response = await fetch(targetUrl, {
            method: "GET",
            redirect: "follow",
            headers: {
              "User-Agent": "PQC-Readiness-War-Room/0.4",
            },
          });

          const headers = response.headers;

          const signals = {
            target,
            valid: true,
            reachable: true,
            finalUrl: response.url,
            status: response.status,
            limited:
              response.status === 401 ||
              response.status === 403 ||
              response.status === 429 ||
              response.status === 503,
            httpsRedirectOrSuccess: response.url.startsWith("https://"),
            hsts: headerValue(headers, "strict-transport-security"),
            altSvc: headerValue(headers, "alt-svc"),
            csp: headerValue(headers, "content-security-policy"),
            xFrameOptions: headerValue(headers, "x-frame-options"),
            xContentTypeOptions: headerValue(headers, "x-content-type-options"),
            referrerPolicy: headerValue(headers, "referrer-policy"),
            permissionsPolicy: headerValue(headers, "permissions-policy"),
            server: headerValue(headers, "server"),
            cfCacheStatus: headerValue(headers, "cf-cache-status"),
          };

          targetAssessment = {
            ...signals,
            score: scoreTargetSignals(signals),
            confidence: confidenceFromTarget(signals),
          };
        } catch (err) {
          targetAssessment = {
            target,
            valid: true,
            reachable: false,
            error: err.message || "Fetch failed.",
            score: 0,
            confidence: "LOW",
          };
        }
      }
    }

    const pqcMigrationAnalysis = buildPqcMigrationAnalysis({
      tlsIsModern,
      httpIsModern,
      usesHttp3,
      cipherIsAead,
      targetAssessment,
      discoveryAssessed: cryptoDiscovery.status !== "NOT ASSESSED",
    });

    const recommendation =
      tlsModernizationScore >= 75
        ? "Strong TLS modernization posture. Next step: inventory cryptographic dependencies, validate vendor PQC roadmaps, and map visibility requirements."
        : tlsModernizationScore >= 55
          ? "Moderate TLS modernization posture. Next step: confirm TLS 1.3 coverage, document visibility gaps, and begin PQC readiness planning."
          : "Weak TLS modernization posture. Next step: prioritize TLS modernization, remove legacy protocol dependencies, and establish crypto-agility governance.";

    console.log(
      "PQC_READINESS_SCAN",
      JSON.stringify({
        event: "pqc_readiness_scan",
        tlsModernizationScore,
        modernizationPosture,
        pqcReadinessScore,
        pqcReadinessLevel,
        cryptoAgilityScore: null,
        cryptoAgilityStatus,
        targetAssessment,
        protocol,
        tlsVersion,
        cipher,
        colo,
        country,
        city,
        region,
        asn,
        asOrg,
        echStatus,
        pqcVerified,
        visibilityImpact,
        pqcMigrationReadiness: pqcMigrationAnalysis.level,
        pqcMigrationReadinessScore: pqcMigrationAnalysis.score,
        pqcMigrationReadinessCappedByDiscovery:
          pqcMigrationAnalysis.cappedByDiscovery,
        timestamp: new Date().toISOString(),
      }),
    );

    const findingRows = findings
      .map((f) => {
        const cls =
          f.status === "PASS"
            ? "pass"
            : f.status === "FAIL"
              ? "fail"
              : f.status === "WARN"
                ? "warn"
                : "info";

        return `
        <div class="finding ${cls}">
          <div class="finding-top">
            <span class="badge ${cls}">${f.status}</span>
            <span class="finding-title">${f.label}</span>
          </div>
          <div class="finding-detail">${f.detail}</div>
        </div>
      `;
      })
      .join("");

    const observedReadinessRows = pqcMigrationAnalysis.observed.length
      ? pqcMigrationAnalysis.observed.map((item) => analysisLine(`✓ ${item}`)).join("")
      : analysisLine("No positive migration readiness signals observed yet");

    const readinessGapRows = pqcMigrationAnalysis.gaps.length
      ? pqcMigrationAnalysis.gaps.map((item) => analysisLine(`□ ${item}`)).join("")
      : analysisLine("No major observed-signal gaps from this assessment");

    const readinessUnknownRows = pqcMigrationAnalysis.unknowns
      .map((item) => analysisLine(`? ${item}`))
      .join("");

    const cryptoDiscoveryRequiredRows = cryptoDiscovery.requiredEvidence
      .map((item) => analysisLine(`□ ${item}`))
      .join("");

    const cryptoDiscoveryCoverageRows = cryptoDiscovery.currentCoverage
      .map((item) => analysisLine(`✓ ${item}`))
      .join("");

    const cryptoDiscoveryNotCoveredRows = cryptoDiscovery.notCovered
      .map((item) => analysisLine(`? ${item}`))
      .join("");

    const validationPriorityOneRows = validationPlan.priorityOne
      .map((item) => analysisLine(`□ ${item}`))
      .join("");

    const validationPriorityTwoRows = validationPlan.priorityTwo
      .map((item) => analysisLine(`□ ${item}`))
      .join("");

    const validationDoNotInferRows = validationPlan.doNotInfer
      .map((item) => analysisLine(`? ${item}`))
      .join("");

    const targetHtml = targetAssessment
      ? targetAssessment.reachable
        ? `
          <div class="metric ${
            targetAssessment.score >= 75
              ? "green"
              : targetAssessment.score >= 50
                ? "yellow"
                : "red"
          }">${targetAssessment.score}/100</div>
          <div class="bar">
            <div class="${
              targetAssessment.score >= 75
                ? "fill"
                : targetAssessment.score >= 50
                  ? "fill-yellow"
                  : "fill-red"
            }" style="width:${targetAssessment.score}%"></div>
          </div>

          <div class="small">Target: <b>${targetAssessment.target}</b></div>
          <div class="kv"><span class="label">Confidence:</span><span class="value">${targetAssessment.confidence}</span></div>
          <div class="kv"><span class="label">HTTP Status:</span><span class="value">${targetAssessment.status}</span></div>
          <div class="kv"><span class="label">Final URL:</span><span class="value">${targetAssessment.finalUrl}</span></div>
          <div class="kv"><span class="label">Alt-Svc:</span><span class="value">${targetAssessment.altSvc}</span></div>
          <div class="kv"><span class="label">HSTS:</span><span class="value">${targetAssessment.hsts}</span></div>
          <div class="kv"><span class="label">CSP:</span><span class="value">${targetAssessment.csp === "Not observed" ? "Not observed" : "Observed"}</span></div>
          <div class="kv"><span class="label">Server:</span><span class="value">${targetAssessment.server}</span></div>

          ${
            targetAssessment.limited
              ? `<div class="warning-box">
                  Assessment Limited: The target returned a challenge, denial, or rate-limit response. Header signals may reflect a challenge page or intermediary response rather than the target's normal application posture.
                </div>`
              : ""
          }

          <h3>Observed Signals</h3>
          <div class="signal-list">
            ${signalLine(targetAssessment.reachable, "HTTPS endpoint reachable")}
            ${signalLine(targetAssessment.httpsRedirectOrSuccess, "HTTPS final URL")}
            ${signalLine(targetAssessment.status >= 200 && targetAssessment.status < 400, `HTTP response returned (${targetAssessment.status})`)}
            ${signalLine(targetAssessment.hsts !== "Not observed", "HSTS observed")}
            ${signalLine(targetAssessment.altSvc.toLowerCase().includes("h3"), "HTTP/3 advertised through Alt-Svc")}
            ${signalLine(targetAssessment.csp !== "Not observed", "Content Security Policy observed")}
            ${signalLine(targetAssessment.xFrameOptions !== "Not observed", "X-Frame-Options observed")}
            ${signalLine(targetAssessment.xContentTypeOptions !== "Not observed", "X-Content-Type-Options observed")}
            ${signalLine(targetAssessment.referrerPolicy !== "Not observed", "Referrer-Policy observed")}
            ${signalLine(targetAssessment.permissionsPolicy !== "Not observed", "Permissions-Policy observed")}
          </div>

          <h3>Unknown Signals</h3>
          <div class="signal-list">
            <div class="signal unknown">? ML-KEM support</div>
            <div class="signal unknown">? Hybrid PQC key exchange support</div>
            <div class="signal unknown">? ECH support</div>
            <div class="signal unknown">? Certificate agility</div>
            <div class="signal unknown">? Cryptographic inventory coverage</div>
            <div class="signal unknown">? Vendor PQC migration roadmap</div>
          </div>
        `
        : `
          <div class="metric red">FAILED</div>
          <div class="small">Target: <b>${targetAssessment.target}</b></div>
          <div class="value">Reason: ${targetAssessment.error}</div>
        `
      : `
        <div class="metric yellow">NO TARGET</div>
        <div class="small">Enter a public domain to run a lightweight HTTPS posture assessment.</div>
      `;

    const html = `
<!DOCTYPE html>
<html>
<head>
<title>PQC Readiness War Room</title>
<style>
* { box-sizing: border-box; }

body {
  margin: 0;
  background: #070b10;
  color: #d7fff8;
  font-family: Consolas, Monaco, monospace;
}

.wrapper {
  max-width: 1500px;
  margin: 0 auto;
  padding: 28px;
}

h1 {
  margin: 0;
  color: #ffffff;
  font-size: 34px;
}

h3 {
  color: #ffffff;
  margin: 18px 0 8px;
  font-size: 15px;
}

.subtitle {
  color: #8fa7b7;
  margin: 8px 0 22px;
  font-size: 15px;
}

.banner {
  border: 1px solid #00ffcc;
  background: #0e171f;
  padding: 16px;
  margin-bottom: 18px;
  color: #ffffff;
  line-height: 1.55;
}

.scan-form {
  display: flex;
  gap: 10px;
  margin-bottom: 18px;
  flex-wrap: wrap;
}

input {
  background: #071014;
  color: #ffffff;
  border: 1px solid rgba(0, 255, 204, 0.7);
  padding: 12px;
  min-width: 360px;
  font-family: inherit;
}

button {
  background: #111820;
  color: #00ffcc;
  border: 1px solid #00ffcc;
  padding: 11px 14px;
  cursor: pointer;
  font-family: inherit;
  font-weight: bold;
}

button:hover {
  background: #00ffcc;
  color: #071014;
}

.grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}

.card {
  background: #101820;
  border: 1px solid rgba(0, 255, 204, 0.7);
  padding: 18px;
  min-height: 175px;
}

.card h2 {
  color: #ffffff;
  margin: 0 0 16px;
  font-size: 19px;
}

.span-3 { grid-column: span 3; }
.span-4 { grid-column: span 4; }
.span-5 { grid-column: span 5; }
.span-6 { grid-column: span 6; }
.span-7 { grid-column: span 7; }
.span-8 { grid-column: span 8; }
.span-12 { grid-column: span 12; }

@media (max-width: 1100px) {
  .span-3, .span-4, .span-5, .span-6, .span-7, .span-8, .span-12 {
    grid-column: span 12;
  }
}

.label {
  color: #88fff0;
  font-weight: bold;
}

.value {
  color: #ffffff;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.metric {
  color: #ffffff;
  font-size: 38px;
  font-weight: bold;
  margin: 8px 0;
}

.summary-card .metric {
  font-size: 31px;
  overflow-wrap: anywhere;
}

.green { color: #00ffcc; }
.red { color: #ff4d4d; }
.yellow { color: #ffd166; }
.blue { color: #8ab4ff; }

.bar {
  width: 100%;
  height: 18px;
  background: #26323d;
  margin-top: 8px;
  margin-bottom: 14px;
  overflow: hidden;
}

.fill {
  height: 100%;
  background: #00ffcc;
}

.fill-yellow {
  height: 100%;
  background: #ffd166;
}

.fill-red {
  height: 100%;
  background: #ff4d4d;
}

.kv {
  display: grid;
  grid-template-columns: 165px 1fr;
  gap: 8px;
  margin: 6px 0;
}

.finding {
  border: 1px solid rgba(255,255,255,0.12);
  padding: 12px;
  margin-bottom: 10px;
  background: #071014;
}

.finding.pass { border-color: rgba(0, 255, 204, 0.65); }
.finding.warn { border-color: rgba(255, 209, 102, 0.75); }
.finding.fail { border-color: rgba(255, 77, 77, 0.75); }
.finding.info { border-color: rgba(138, 180, 255, 0.65); }

.finding-top {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}

.finding-title {
  color: #ffffff;
  font-weight: bold;
}

.finding-detail {
  color: #c8d7e1;
  font-size: 13px;
  line-height: 1.45;
}

.badge {
  display: inline-block;
  padding: 3px 7px;
  border: 1px solid currentColor;
  font-size: 12px;
}

.badge.pass { color: #00ffcc; }
.badge.warn { color: #ffd166; }
.badge.fail { color: #ff4d4d; }
.badge.info { color: #8ab4ff; }

.pill {
  display: inline-block;
  padding: 5px 8px;
  border: 1px solid currentColor;
  margin-right: 8px;
  margin-bottom: 8px;
  font-size: 13px;
}

.small {
  color: #9fb3c8;
  font-size: 13px;
  margin-top: 12px;
  line-height: 1.5;
}

.assessment-row {
  display: grid;
  grid-template-columns: 190px 1fr;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid rgba(255,255,255,0.08);
}

.assessment-row:last-child {
  border-bottom: none;
}

.status-unknown {
  color: #ffd166;
}

.checkbox-line {
  padding: 5px 0;
  color: #c8d7e1;
}

.signal-list {
  border: 1px solid rgba(255,255,255,0.12);
  background: #071014;
  padding: 10px;
}

.signal {
  padding: 5px 0;
  font-size: 13px;
}

.signal.observed {
  color: #00ffcc;
}

.signal.missing {
  color: #ff4d4d;
}

.signal.unknown {
  color: #ffd166;
}

.warning-box {
  margin-top: 12px;
  border: 1px solid #ffd166;
  color: #ffd166;
  background: #191507;
  padding: 10px;
  line-height: 1.45;
  font-size: 13px;
}

.footer {
  color: #8fa7b7;
  margin-top: 18px;
  font-size: 13px;
}
</style>
</head>

<body>
<div class="wrapper">
  <h1>PQC Readiness War Room</h1>
  <div class="subtitle">Edge-based TLS modernization, target HTTPS posture, protocol visibility, and crypto-agility model.</div>

  <div class="banner">
    <b>Simulation: PQC Readiness Posture Model</b><br><br>
    This Worker observes browser-to-edge metadata and performs a lightweight HTTPS posture assessment of a public target domain.
    It is not a full cryptographic scanner. It separates observed signals from unknown signals so readiness is not overstated.
  </div>

  <form class="scan-form" method="GET">
    <input name="target" placeholder="Enter target domain, e.g. nist.gov" value="${target || ""}">
    <button type="submit">Run Target Assessment</button>
    <button type="button" onclick="window.location='/'">Clear</button>
  </form>

  <div class="grid">

    <div class="card summary-card span-3">
      <h2>TLS Modernization</h2>
      <div class="metric ${tlsModernizationScore >= 75 ? "green" : tlsModernizationScore >= 55 ? "yellow" : "red"}">${modernizationPosture}</div>
      <div class="bar">
        <div class="${tlsModernizationScore >= 75 ? "fill" : tlsModernizationScore >= 55 ? "fill-yellow" : "fill-red"}" style="width:${tlsModernizationScore}%"></div>
      </div>
      <div class="small">Browser-to-edge score: <b>${tlsModernizationScore}/100</b></div>
    </div>

    <div class="card summary-card span-3">
      <h2>PQC Verification</h2>
      <div class="metric ${pqcVerified ? "green" : "red"}">${pqcReadinessLevel}</div>
      <div class="bar">
        <div class="${pqcVerified ? "fill" : "fill-red"}" style="width:${pqcReadinessScore}%"></div>
      </div>
      <div class="small">
        Score: <b>${pqcReadinessScore}/100</b><br>
        PQC support is not directly verified from this Worker alone.
      </div>
    </div>

    <div class="card summary-card span-3">
      <h2>PQC Migration Readiness</h2>
      <div class="metric ${pqcMigrationAnalysis.level === "HIGH" ? "green" : pqcMigrationAnalysis.level === "MEDIUM" ? "yellow" : "red"}">${pqcMigrationAnalysis.level}</div>
      <div class="bar">
        <div class="${pqcMigrationAnalysis.level === "HIGH" ? "fill" : pqcMigrationAnalysis.level === "MEDIUM" ? "fill-yellow" : "fill-red"}" style="width:${pqcMigrationAnalysis.score}%"></div>
      </div>
      <div class="small">
        Score: <b>${pqcMigrationAnalysis.score}/100</b><br>
        ${pqcMigrationAnalysis.reasoning}
      </div>
    </div>

    <div class="card summary-card span-3">
      <h2>Crypto-Agility Status</h2>
      <div class="metric yellow">${cryptoAgilityStatus}</div>
      <div class="small">
        No score is assigned until discovery, inventory, governance, vendor readiness, and migration planning evidence are assessed.
      </div>
    </div>

    <div class="card span-8">
      <h2>Target HTTPS Posture Assessment</h2>
      ${targetHtml}
      <div class="small">
        This target assessment checks HTTPS reachability and selected response headers. It does not enumerate TLS key exchange groups or verify PQC support.
      </div>
    </div>

    <div class="card span-4">
      <h2>Observed Browser-to-Edge Connection</h2>
      <div class="kv"><span class="label">TLS:</span><span class="value">${tlsVersion}</span></div>
      <div class="kv"><span class="label">HTTP:</span><span class="value">${protocol}</span></div>
      <div class="kv"><span class="label">Cipher:</span><span class="value">${cipher}</span></div>
      <div class="kv"><span class="label">Edge:</span><span class="value">${colo}</span></div>
      <div class="kv"><span class="label">Visibility:</span><span class="value">${visibilityImpact}</span></div>
    </div>

    <div class="card span-4">
      <h2>Protocol Intelligence</h2>
      <div class="kv"><span class="label">Protocol:</span><span class="value">${protocolIntelligence.protocol}</span></div>
      <div class="kv"><span class="label">Interpretation:</span><span class="value">${protocolIntelligence.interpretation}</span></div>
      <h3>Why It Matters</h3>
      <div class="value">${protocolIntelligence.whyItMatters}</div>
      <h3>${protocolIntelligence.guidanceHeading}</h3>
      <div class="value">${protocolIntelligence.operationalImpact}</div>
      <h3>Recommended Telemetry</h3>
      <div class="value">${protocolIntelligence.telemetrySources}</div>
    </div>

    <div class="card span-4">
      <h2>Modernization Signals</h2>
      <span class="pill ${tlsIsModern ? "green" : "red"}">TLS 1.3: ${tlsIsModern ? "Observed" : "Not observed"}</span>
      <span class="pill ${httpIsModern ? "green" : "yellow"}">HTTP: ${protocol}</span>
      <span class="pill ${cipherIsAead ? "green" : "yellow"}">AEAD Cipher: ${cipherIsAead ? "Likely" : "Unknown"}</span>
      <span class="pill blue">ECH: ${echStatus}</span>
      <span class="pill yellow">PQC Verified: Not from Worker alone</span>
    </div>

    <div class="card span-4">
      <h2>Location and Network Context</h2>
      <div class="kv"><span class="label">Country:</span><span class="value">${country}</span></div>
      <div class="kv"><span class="label">City:</span><span class="value">${city}</span></div>
      <div class="kv"><span class="label">Region:</span><span class="value">${region}</span></div>
      <div class="kv"><span class="label">ASN:</span><span class="value">${asn}</span></div>
      <div class="kv"><span class="label">AS Org:</span><span class="value">${asOrg}</span></div>
    </div>

    <div class="card span-4">
      <h2>Crypto-Agility Assessment</h2>
      <div class="assessment-row"><span class="label">Discovery</span><span class="status-unknown">UNKNOWN</span></div>
      <div class="assessment-row"><span class="label">Inventory</span><span class="status-unknown">UNKNOWN</span></div>
      <div class="assessment-row"><span class="label">Governance</span><span class="status-unknown">UNKNOWN</span></div>
      <div class="assessment-row"><span class="label">Vendor Readiness</span><span class="status-unknown">UNKNOWN</span></div>
      <div class="assessment-row"><span class="label">Migration Planning</span><span class="status-unknown">UNKNOWN</span></div>
      <div class="small">
        Organizational crypto-agility requires discovery, inventory, ownership, and migration planning inputs.
      </div>
    </div>

    <div class="card span-8">
      <h2>Crypto Discovery</h2>
      <div class="metric yellow">${cryptoDiscovery.status}</div>
      <div class="small">
        Discovery evidence is required before a migration plan can be trusted. This Worker does not perform endpoint inventory, source analysis, uploads, or database-backed discovery.
      </div>
      <h3>Required Evidence</h3>
      <div class="signal-list">${cryptoDiscoveryRequiredRows}</div>
      <h3>Current Tool Coverage</h3>
      <div class="signal-list">${cryptoDiscoveryCoverageRows}</div>
      <h3>Not Covered</h3>
      <div class="signal-list">${cryptoDiscoveryNotCoveredRows}</div>
    </div>

    <div class="card span-8">
      <h2>PQC Readiness Analysis</h2>
      <h3>Observed Modernization Evidence</h3>
      <div class="signal-list">${observedReadinessRows}</div>
      <h3>Readiness Gaps</h3>
      <div class="signal-list">${readinessGapRows}</div>
      <h3>Unknown Signals</h3>
      <div class="signal-list">${readinessUnknownRows}</div>
      <div class="small">
        This analysis estimates migration preparedness from observable posture signals. It does not verify PQC support or enumerate TLS key exchange groups.
      </div>
    </div>

    <div class="card span-7">
      <h2>Readiness Findings</h2>
      ${findingRows}
    </div>

    <div class="card span-5">
      <h2>Recommendation</h2>
      <div class="value">${recommendation}</div>
      <div class="small">
        Practical next step: inventory TLS endpoints, map crypto dependencies, validate vendor PQC roadmaps, and define visibility requirements before migration.
      </div>
    </div>

    <div class="card span-7">
      <h2>Validation Plan</h2>
      <h3>Priority 1</h3>
      <div class="signal-list">${validationPriorityOneRows}</div>
      <h3>Priority 2</h3>
      <div class="signal-list">${validationPriorityTwoRows}</div>
      <h3>Do Not Infer</h3>
      <div class="signal-list">${validationDoNotInferRows}</div>
      <div class="small">
        Use this plan to move from posture observations to evidence collection without treating unknown signals as verified.
      </div>
    </div>

    <div class="card span-6">
      <h2>Platform Roadmap</h2>
      <div class="checkbox-line">✓ Phase 1: TLS Modernization</div>
      <div class="checkbox-line">✓ Phase 2: HTTPS Posture Assessment</div>
      <div class="checkbox-line">✓ Phase 3: PQC Readiness Analysis</div>
      <div class="checkbox-line">✓ Phase 4: Crypto Discovery Evidence Model</div>
      <div class="checkbox-line">✓ Phase 5: Validation Plan</div>
      <div class="checkbox-line">□ Phase 6: Migration Planning</div>
    </div>

    <div class="card span-6">
      <h2>What This Cannot Prove Alone</h2>
      <div class="value">
        <ul>
          <li>It cannot fully enumerate supported TLS key exchange groups.</li>
          <li>It cannot prove PQC or hybrid KEM support by itself.</li>
          <li>It cannot determine full enterprise crypto inventory.</li>
          <li>It cannot replace active scanning, endpoint inventory, vendor validation, or governance assessment.</li>
        </ul>
      </div>
    </div>

    <div class="card span-12">
      <h2>Executive Takeaway</h2>
      <div class="value">
        A modern TLS posture is a prerequisite for PQC migration, but it is not proof of PQC readiness.
        True readiness requires cryptographic discovery, inventory, governance, vendor validation, and migration planning.
      </div>
    </div>

  </div>

  <div class="footer">
    Simulation note: This is a posture model, not a full cryptographic scanner. Use it to explain observed signals, unknowns, and next-step validation requirements.
  </div>
</div>
</body>
</html>
`;

    return new Response(html, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
    });
  },
};
