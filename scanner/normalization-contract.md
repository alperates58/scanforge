# Finding Normalization Contract

Every tool result must become:

{
  "title": "Missing Content-Security-Policy header",
  "severity": "medium",
  "confidence": 0.9,
  "affected_url": "https://example.com/",
  "source_tool": "headers",
  "cwe": "CWE-693",
  "cve": null,
  "cvss": null,
  "owasp_category": "A05 Security Misconfiguration",
  "evidence": "Content-Security-Policy header not present",
  "remediation": "Add a strict CSP header.",
  "fingerprint_hash": "stable hash for dedupe"
}
