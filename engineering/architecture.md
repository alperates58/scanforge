# Architecture

## Components

1. Frontend App
- React/Vite/TypeScript
- Premium dashboard
- API client

2. Backend API
- Auth, websites, scans, findings, reports
- Job dispatcher
- AI analysis service

3. Scanner Worker
- Runs tools in isolated jobs
- Nuclei, ZAP, httpx, dnsx, testssl, WhatWeb/Wappalyzer, WPScan
- Produces raw artifacts + normalized findings

4. PostgreSQL
- Source of truth

5. Redis Queue
- Scan job queue, progress updates

6. Object Storage / Local Volume
- Raw scan outputs
- Report files

## Flow
URL -> website registry -> verification -> discovery -> tech fingerprint -> scanner matrix -> scan jobs -> normalize -> score -> AI analysis -> dashboard/report.
