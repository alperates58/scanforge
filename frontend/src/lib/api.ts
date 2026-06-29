export type DashboardSummary = {
  schema_ready: boolean;
  totals: {
    websites: number;
    verified_websites: number;
    scans: number;
    open_findings: number;
    passive_findings?: number;
    discoveries?: number;
  };
  risk: {
    average_score: number;
    critical_findings: number;
    high_findings: number;
  };
  activity: {
    scans_this_week: number;
    latest_scan_status: string | null;
    last_discovery_at?: string | null;
    latest_discovery_status?: string | null;
  };
  safety: {
    unverified_domain_scans_allowed: boolean;
    default_safe_mode: boolean;
    workspace_concurrent_scan_limit: number;
  };
  workspace?: {
    id: number;
    plan_name: string;
    monthly_scan_limit: number;
    scans_used_this_month: number;
  };
  worker_metrics?: {
    active_workers: number;
    active_jobs: number;
    queued_jobs: number;
    failed_jobs: number;
    avg_job_time: number;
  };
};

export type HealthStatus = {
  status: 'ok' | 'degraded';
  service: string;
  environment: string;
  version: string;
  dependencies: Record<string, { ok: boolean; error?: string }>;
};

const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';
const TOKEN_KEY = 'scanforge_token';

export type User = {
  id: number;
  name: string;
  email: string;
};

export type Workspace = {
  id: number;
  name: string;
  plan_name: string;
  monthly_scan_limit: number;
  concurrent_scan_limit: number;
  scans_used_this_month: number;
  role?: string | null;
};

export type AuthPayload = {
  user: User;
  workspace: Workspace | null;
  token: string;
};

export type Website = {
  id: number;
  workspace_id: number;
  url: string;
  scheme: string;
  host: string;
  root_domain: string;
  normalized_host: string;
  environment: 'production' | 'staging' | 'development' | 'other';
  importance: 'low' | 'normal' | 'high' | 'critical';
  status: string;
  verification_status: string;
  verification_method: string | null;
  verification_last_checked_at: string | null;
  ownership_verified_at: string | null;
  verified_at: string | null;
  security_score: number | null;
  risk_score: number | null;
  last_scan_score: number | null;
  last_scan_at: string | null;
  discovery_completed_at: string | null;
  last_observed_at: string | null;
  notes: string | null;
  tags: string[];
  created_at: string | null;
};

export type AssetDiscovery = {
  id: number;
  website_id: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'timeout';
  started_at: string | null;
  dns_completed_at: string | null;
  http_completed_at: string | null;
  ssl_completed_at: string | null;
  whois_completed_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  discovery_score: number | null;
  analysis_required: boolean;
  metrics: {
    total_dns_records: number;
    total_ips: number;
    total_headers: number;
    total_cookies: number;
    total_findings: number;
    technologies_detected: number;
  };
  summary: Record<string, unknown> | null;
  error_message: string | null;
  created_at: string | null;
};

export type AssetSummary = {
  host: string;
  last_discovery: AssetDiscovery | null;
  ip_addresses: Array<{
    ip: string;
    ip_version: number;
    is_public: boolean;
    provider: string | null;
    reverse_dns: string | null;
  }>;
  dns_record_counts: Record<string, number>;
  ssl: {
    available: boolean;
    days_remaining: number | null;
    issuer: string | null;
    valid_to: string | null;
  } | null;
  http: {
    status_code: number | null;
    title: string | null;
    server: string | null;
    powered_by: string | null;
    favicon_hash: string | null;
    final_url: string | null;
  } | null;
  security_headers: Record<string, { present: boolean; value: string | null; recommendation: string }>;
  cookies: {
    total: number;
    secure: number;
    http_only: number;
    same_site: number;
    persistent: number;
  };
  robots?: { available: boolean; status_code: number | null; sensitive_paths: string[] } | null;
  sitemap?: { available: boolean; status_code: number | null; sensitive_paths: string[] } | null;
  whois: { registrar: string | null; age_days: number | null; status: string | null } | null;
  subdomain_count: number;
  passive_findings: Array<{ id: number; title: string; severity: string; status: string }>;
  technologies: Array<{ technology_key?: string | null; name: string; category: string | null; confidence_score: number; quality_score?: number; detection_source: string | null; evidence: unknown }>;
};

export type TechnologyFingerprint = {
  id: number;
  technology_key: string;
  name: string;
  category: string | null;
  version: string | null;
  confidence_score: number;
  quality_score: number;
  cpe_candidates: Array<{ confidence: number; source: string; cpe: string; version: string }>;
  analysis_required: boolean;
  analysis_version: string;
  metadata: Record<string, unknown> | null;
  last_detected_at: string | null;
  evidence?: Array<{
    source_type: string;
    source_key: string | null;
    source_value: string | null;
    confidence: number;
    raw_data: Record<string, unknown> | null;
    detected_at: string | null;
  }>;
};

export type TechnologyCoverage = {
  percentage: number;
  covered: number;
  total: number;
  items: Record<string, { present: boolean; label: string }>;
};

export type TechnologyRelationship = {
  parent: string;
  child: string;
  type: string;
  confidence: number;
  parent_name?: string | null;
  child_name?: string | null;
};

export type TechnologyConflict = {
  category: string;
  severity: string;
  reason: string;
  left: string | null;
  right: string | null;
  detected_at: string | null;
};

export type TechnologySummary = {
  technologies: TechnologyFingerprint[];
  coverage: TechnologyCoverage;
  relationships: TechnologyRelationship[];
  conflicts: TechnologyConflict[];
};

export type TechnologyGraph = {
  website: {
    id: number;
    host: string;
    environment: string;
    importance: string;
    verification_status: string;
  };
  asset_graph: {
    host: string;
    ssl: { available: boolean; issuer: string | null; days_remaining: number | null };
    headers: Record<string, unknown>;
    cookies: string[];
  };
  technologies: Array<{
    id: number;
    key: string;
    name: string;
    category: string | null;
    version: string | null;
    confidence_score: number;
    quality_score: number;
    analysis_required: boolean;
    analysis_version: string;
  }>;
  relationships: Array<{ from: string; to: string; type: string; confidence: number }>;
  latest_scan_plan: {
    id: number;
    coverage_prediction: number;
    estimated_runtime_seconds: number;
    estimated_requests: number;
    estimated_cpu: number;
    estimated_memory_mb: number;
    items: number;
  } | null;
};

export type ScanPlan = {
  id: number;
  website_id: number;
  asset_discovery_id: number | null;
  status: string;
  coverage_prediction: number;
  estimated_runtime_seconds: number;
  estimated_requests: number;
  estimated_cpu: number;
  estimated_memory_mb: number;
  safe_mode: boolean;
  analysis_required: boolean;
  summary: Record<string, unknown> | null;
  generated_at: string | null;
  items: Array<{
    id: number;
    technology_key: string;
    scanner_key: string;
    template_group: string;
    scan_module: string;
    priority: number;
    recommendation_score: number;
    estimated_duration_seconds: number;
    estimated_requests: number;
    estimated_cpu: number;
    estimated_memory_mb: number;
    safe_mode: boolean;
    reason: string | null;
    metadata: Record<string, unknown> | null;
  }>;
};

export type ScanJobRecord = {
  id: number;
  scan_plan_item_id: number | null;
  scanner_key: string | null;
  scan_module: string | null;
  template_group: string | null;
  status: string;
  queue_name: string;
  priority: number;
  recommendation_score: number;
  safe_default: boolean;
  attempt_count: number;
  max_attempts: number;
  timeout_seconds: number | null;
  progress_percent: number;
  request_count: number;
  max_requests: number | null;
  max_runtime: number | null;
  max_memory: number | null;
  worker_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  result_summary: Record<string, unknown> | null;
  error_message: string | null;
  plan_item: {
    technology_key: string;
    reason: string | null;
  } | null;
};

export type ScanRecord = {
  id: number;
  workspace_id: number;
  website_id: number;
  scan_plan_id: number | null;
  status: string;
  scan_type: string;
  safety_mode: string;
  request_budget: number | null;
  timeout_seconds: number | null;
  progress_percent: number;
  total_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  skipped_jobs: number;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  duration_ms: number | null;
  error_message: string | null;
  plan: {
    id: number;
    status: string;
    coverage_prediction: number;
    estimated_requests: number;
  } | null;
  recent_findings: unknown[];
  artifacts_count: number;
  created_at: string | null;
  jobs?: ScanJobRecord[];
};

export type VerificationMethod = {
  method: 'dns_txt' | 'html_file' | 'meta_tag';
  label: string;
  status: string;
  host?: string;
  record_type?: string;
  record_value?: string;
  path?: string;
  expected_body?: string;
  tag?: string;
};

export type VerificationPayload = {
  website_id?: number;
  host?: string;
  verification_status?: string;
  token: string;
  methods: VerificationMethod[];
};

export type VerificationCheckResult = {
  website_id: number;
  verified: boolean;
  verified_method: string | null;
  methods: Array<{
    method: string;
    status: string;
    checked_at: string;
    error: string | null;
  }>;
};

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly errors?: Record<string, string[]>,
  ) {
    super(message);
  }
}

type ApiEnvelope<T> = {
  data: T;
  meta?: Record<string, unknown>;
};

type RequestOptions = {
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
  auth?: boolean;
};

export function getStoredToken(): string | null {
  return window.localStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
}

async function requestJson<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (options.auth !== false) {
    const token = getStoredToken();

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new ApiError(payload?.message ?? `API request failed: ${response.status}`, response.status, payload?.errors);
  }

  return response.json() as Promise<T>;
}

async function envelope<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const payload = await requestJson<ApiEnvelope<T>>(path, options);

  return payload.data;
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  return requestJson<DashboardSummary>('/api/dashboard/summary');
}

export async function fetchHealth(): Promise<HealthStatus> {
  return requestJson<HealthStatus>('/api/health', { auth: false });
}

export async function register(payload: { name: string; email: string; password: string }): Promise<AuthPayload> {
  return envelope<AuthPayload>('/api/auth/register', {
    method: 'POST',
    body: payload,
    auth: false,
  });
}

export async function login(payload: { email: string; password: string }): Promise<AuthPayload> {
  return envelope<AuthPayload>('/api/auth/login', {
    method: 'POST',
    body: payload,
    auth: false,
  });
}

export async function logout(): Promise<void> {
  await envelope<{ logged_out: boolean }>('/api/auth/logout', { method: 'POST' });
  clearToken();
}

export async function fetchMe(): Promise<{ user: User; workspaces: Workspace[] }> {
  return envelope<{ user: User; workspaces: Workspace[] }>('/api/me');
}

export async function fetchWebsites(): Promise<Website[]> {
  return envelope<Website[]>('/api/websites');
}

export async function fetchWebsite(websiteId: string): Promise<Website> {
  return envelope<Website>(`/api/websites/${websiteId}`);
}

export async function createWebsite(payload: {
  url: string;
  environment: Website['environment'];
  importance: Website['importance'];
  notes?: string;
  tags?: string[];
}): Promise<{ website: Website; verification: VerificationPayload }> {
  return envelope<{ website: Website; verification: VerificationPayload }>('/api/websites', {
    method: 'POST',
    body: payload,
  });
}

export async function fetchVerification(websiteId: string): Promise<VerificationPayload> {
  return envelope<VerificationPayload>(`/api/websites/${websiteId}/verification`);
}

export async function checkVerification(websiteId: string): Promise<VerificationCheckResult> {
  return envelope<VerificationCheckResult>(`/api/websites/${websiteId}/verification/check`, {
    method: 'POST',
  });
}

export async function runDiscovery(websiteId: string): Promise<AssetDiscovery> {
  return envelope<AssetDiscovery>(`/api/websites/${websiteId}/discoveries`, {
    method: 'POST',
  });
}

export async function fetchDiscoveries(websiteId: string): Promise<AssetDiscovery[]> {
  return envelope<AssetDiscovery[]>(`/api/websites/${websiteId}/discoveries`);
}

export async function fetchAssetSummary(websiteId: string): Promise<AssetSummary> {
  return envelope<AssetSummary>(`/api/websites/${websiteId}/assets/summary`);
}

export async function runFingerprint(websiteId: string): Promise<TechnologySummary> {
  return envelope<TechnologySummary>(`/api/websites/${websiteId}/fingerprint`, {
    method: 'POST',
  });
}

export async function fetchTechnologySummary(websiteId: string): Promise<TechnologySummary> {
  return envelope<TechnologySummary>(`/api/websites/${websiteId}/technologies`);
}

export async function fetchTechnologyGraph(websiteId: string): Promise<TechnologyGraph> {
  return envelope<TechnologyGraph>(`/api/websites/${websiteId}/technology-graph`);
}

export async function generateScanPlan(websiteId: string): Promise<ScanPlan> {
  return envelope<ScanPlan>(`/api/websites/${websiteId}/scan-plans`, {
    method: 'POST',
  });
}

export async function fetchScanPlans(websiteId: string): Promise<ScanPlan[]> {
  return envelope<ScanPlan[]>(`/api/websites/${websiteId}/scan-plans`);
}

export async function fetchScans(websiteId: string): Promise<ScanRecord[]> {
  return envelope<ScanRecord[]>(`/api/websites/${websiteId}/scans`);
}

export async function fetchScan(websiteId: string, scanId: string | number): Promise<ScanRecord> {
  return envelope<ScanRecord>(`/api/websites/${websiteId}/scans/${scanId}`);
}

export async function startScan(
  websiteId: string,
  payload: {
    scan_type: 'passive' | 'standard' | 'deep' | 'authenticated';
    consent_accepted: boolean;
    scan_plan_id?: number;
    safety_mode?: 'safe' | 'standard' | 'deep' | 'authenticated';
    credential_id?: number;
    options?: Record<string, unknown>;
  },
): Promise<ScanRecord> {
  return envelope<ScanRecord>(`/api/websites/${websiteId}/scans`, {
    method: 'POST',
    body: payload,
  });
}

export async function cancelScan(websiteId: string, scanId: number): Promise<ScanRecord> {
  return envelope<ScanRecord>(`/api/websites/${websiteId}/scans/${scanId}/cancel`, {
    method: 'POST',
  });
}

export async function retryFailedScan(websiteId: string, scanId: number): Promise<ScanRecord> {
  return envelope<ScanRecord>(`/api/websites/${websiteId}/scans/${scanId}/retry-failed`, {
    method: 'POST',
  });
}
