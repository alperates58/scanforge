# Finding Normalization

Tum scanner ciktilari tek bulgu formatina indirgenir. Bu sayede skor, dedupe, UI ve AI Analyst ayni veri modeliyle calisir.

## Required Fields

- `title`
- `severity`: info, low, medium, high, critical
- `confidence`: 0.0-1.0
- `affected_url`
- `source_tool`
- `evidence`

## Optional Fields

- `cwe`
- `cve`
- `cvss`
- `owasp_category`
- `remediation`
- `fingerprint_hash`
- `raw_artifact_id`

## Dedupe Strategy

`fingerprint_hash` stable olmalidir. Baslangic icin `normalized_host + affected_url + title + source_tool + cve` alanlarindan hash uretilebilir.

## Safety

Evidence alani secrets icermemelidir. Raw response icinde cookie, auth token veya password gorulurse redact edilmelidir.
