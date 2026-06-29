# DeepSeek Analysis Contract

AI receives normalized findings, technology inventory, scan metadata and safe context. AI must not invent findings.

## Input
{
  "website": {},
  "technologies": [],
  "findings": [],
  "scan_summary": {},
  "raw_tool_notes": []
}

## Output
{
  "executive_summary": "...",
  "risk_level": "low|medium|high|critical",
  "business_impact": "...",
  "priority_fixes": [
    {"rank":1,"finding_id":"...","why":"...","estimated_effort":"..."}
  ],
  "false_positive_notes": [],
  "technology_specific_recommendations": [],
  "next_scan_recommendation": "..."
}

## Rules
- Do not claim exploitability unless evidence supports it.
- Clearly mark uncertainty.
- Separate executive language and technical remediation.
- No offensive exploitation instructions.
