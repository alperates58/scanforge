# Technology to Scanner Matrix

## Generic Web
Always run:
- http probe
- redirect chain
- SSL/TLS
- security headers
- cookie flags
- robots/sitemap
- exposed files safe checks
- Nuclei safe generic templates
- ZAP baseline

## PHP detected
Run:
- phpinfo exposure checks
- composer.json/composer.lock exposure checks
- common backup extensions: .bak, .old, .zip with safe wordlist
- PHP CVE templates based on version if detected

## MySQL hints detected
Run:
- phpMyAdmin/Adminer exposed panel checks
- default exposed setup page checks
Do not brute force credentials.

## WordPress detected
Run:
- WPScan API/token if configured
- wp-json enumeration safe mode
- plugin/theme version detection
- known vulnerable plugins/themes mapping
- wp-config backup exposure checks

## Laravel detected
Run:
- .env exposure
- debug mode hints
- Ignition/RCE CVE templates safe check
- storage/log exposure
- APP_DEBUG leak checks

## ASP.NET detected
Run:
- ASP.NET version/header hints
- trace.axd safe check
- web.config exposure
- Telerik/UI known CVE templates if detected

## Node/Next.js detected
Run:
- Next.js version CVE mapping
- sourcemap exposure
- public env leak checks
- common API route discovery via JS analysis

## Nginx detected
Run:
- alias traversal misconfig templates
- default page/admin exposure checks
- weak headers

## Apache detected
Run:
- server-status exposure
- directory listing
- version CVE mapping

## Cloudflare detected
Adjust:
- lower port scan expectations
- identify origin leakage via DNS only in passive mode
- do not attempt bypass.
