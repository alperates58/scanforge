# Phase 07 - Finding Normalization, Correlation and Risk Engine

## Goal

Scanner ve passive discovery ciktisini merkezi finding engine uzerinden canonical modele indirgemek, correlate etmek, risklendirmek ve AI Analyst icin hazir hale getirmek.

## Rules

- Yeni gercek scanner eklenmez.
- Nuclei mevcut safe adapter akisi ile kalir.
- ZAP, WPScan, testssl.sh, httpx, katana, subfinder, ffuf ve nmap bu fazda devre disidir.
- Finding source, evidence, taxonomy, canonical library, risk history, confidence history ve suppression rule kayitlari backend tarafinda uretilir.

## Acceptance

- Nuclei JSONL canonical finding'e normalize edilir.
- Duplicate ve correlated bulgular tek finding altinda `occurrence_count`, source ve correlation score ile birlesir.
- Website risk finding risklerinden rollup edilir.
- Protected findings API ve website detail Findings paneli calisir.
