# Technology Detection Strategy

Technology fingerprinting, hangi scanner kontrollerinin guvenli ve anlamli oldugunu belirlemek icin kullanilir. Tespitler confidence skoruyla saklanir ve tek bir sinyale dayanarak yuksek risk iddiasi uretilmez.

## Signals

- HTTP response headers: server, x-powered-by, framework headers.
- HTML meta tags: generator, framework-specific markers.
- Cookies: framework session cookie isimleri ve security flags.
- Paths: Phase 03 sadece ana HTML icerigindeki public asset path ipuclarini okur; path wordlist veya probing yoktur.
- JavaScript bundles: public framework hints; source map exposure checks Phase 04/05'e birakilir.
- DNS/CDN context: Cloudflare veya managed hosting sinyalleri.
- Favicon hash: SHA-256 hash, ileride Shodan/FOFA/ZoomEye benzeri fingerprint eslesmelerine hazirliktir.

## Confidence Model

- Low confidence, 30-49: tek zayif header, cookie adi veya HTML marker.
- Medium confidence, 50-70: CDN/proxy header'i, generator meta veya birden fazla pasif sinyal.
- High confidence, 71+: Phase 04 ve sonrasi icin ayrilir; canonical endpoint veya version evidence ister.

Phase 04 itibariyla `confidence_score` ve `quality_score` ayridir. Confidence teknolojinin dogruluk ihtimalini; quality kanit sayisi, kanit cesitliligi ve version kanitini temsil eder. Source priority de skora katilir: generator meta 95, header/server 80, cookie 75, HTML/body 60, JS asset 45, favicon 50.

## Phase 03 Coverage

- CDN: Cloudflare, Fastly, CloudFront, Akamai, Bunny, Vercel, Netlify, Azure Front Door, Google Cloud CDN.
- Reverse proxy/server: Nginx, Apache, Caddy, LiteSpeed, OpenResty, IIS.
- Framework/CMS hints: Laravel, Symfony, CodeIgniter, WordPress, Drupal, Joomla, Next.js, Nuxt, React, Vue, Angular, ASP.NET, Spring Boot, Express, Django, Flask.
- Evidence JSON `Header`, `Cookie`, `HTML`, `Generator`, `JS`, `Server`, `Response` kaynaklarini ayirir.

## Phase 04 Plugin Engine

- `FingerprintPluginInterface` yeni teknoloji desteginin ana uzatma noktasidir.
- `RuleGroup` ayni teknoloji icin birden fazla `FingerprintRule` calistirir; WordPress generator, wp-content, cookie, REST API, login path ve RSS sinyallerini birlikte skorlar.
- `TechnologyEvidence` her matched rule'u immutable satir olarak saklar.
- `FingerprintHistory`, `TechnologyRelationship`, `TechnologyConflict` ve coverage metadata AI Analyst icin graph context uretir.
- `CapabilityResolver` teknoloji sonucunu scanner capability kayitlariyla eslestirir; scanner calistirmadan safe scan plan onerisi uretir.

## Scanner Mapping

- Generic Web: headers, cookies, TLS, DNS, safe exposed file checks.
- WordPress: safe version/plugin/theme detection, brute force yok.
- Laravel: `.env` exposure, debug hints, ignition safe checks.
- Node/Next.js: source map exposure, public env leak hints.
- Apache/Nginx: server-status, directory listing, weak header checks.

## Phase Links

- Phase 03 verified passive discovery sirasinda ilk sinyalleri toplar.
- Phase 04 technology fingerprinting sinyalleri zenginlestirir ve confidence modelini sertlestirir.
- Phase 05 technology inventory'yi scan planina baglar.
- Phase 08 CMS ve framework scanner'lari bu inventory'ye gore planlanir.
