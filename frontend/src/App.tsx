import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronRight,
  Copy,
  FileText,
  Fingerprint,
  GitBranch,
  Gauge,
  Globe2,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Plus,
  Radar,
  RotateCcw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  XCircle,
} from 'lucide-react';
import type React from 'react';
import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link, Navigate, Route, Routes, useNavigate, useParams } from 'react-router-dom';
import {
  ApiError,
  AssetDiscovery,
  AssetSummary,
  AuthPayload,
  DashboardSummary,
  FindingDetail,
  FindingFilters,
  FindingListItem,
  FindingSummary,
  HealthStatus,
  ScanRecord,
  ScanPlan,
  TechnologyGraph,
  TechnologyRelationship,
  TechnologySummary,
  VerificationPayload,
  Website,
  cancelScan,
  checkVerification,
  clearToken,
  createWebsite,
  fetchAssetSummary,
  fetchDashboardSummary,
  fetchDiscoveries,
  fetchFinding,
  fetchFindingSummary,
  fetchFindings,
  fetchHealth,
  fetchScan,
  fetchScanPlans,
  fetchScans,
  fetchTechnologyGraph,
  fetchTechnologySummary,
  fetchVerification,
  fetchWebsite,
  fetchWebsites,
  generateScanPlan,
  getStoredToken,
  login,
  logout,
  register,
  retryFailedScan,
  runFingerprint,
  runDiscovery,
  startScan,
  storeToken,
  updateFindingStatus,
} from './lib/api';

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard, to: '/dashboard' },
  { label: 'Websites', icon: Globe2, to: '/websites' },
  { label: 'Attack Surface', icon: Radar, to: '/websites' },
  { label: 'Scans', icon: Search, to: '/dashboard' },
  { label: 'Vulnerabilities', icon: AlertTriangle, to: '/dashboard' },
  { label: 'AI Analyst', icon: Bot, to: '/dashboard' },
  { label: 'Technologies', icon: Fingerprint, to: '/dashboard' },
  { label: 'Reports', icon: FileText, to: '/dashboard' },
  { label: 'Settings', icon: Settings, to: '/dashboard' },
];

const fallbackSummary: DashboardSummary = {
  schema_ready: false,
  totals: {
    websites: 0,
    verified_websites: 0,
    scans: 0,
    open_findings: 0,
    passive_findings: 0,
    discoveries: 0,
  },
  risk: {
    average_score: 0,
    critical_findings: 0,
    high_findings: 0,
  },
  activity: {
    scans_this_week: 0,
    latest_scan_status: null,
    last_discovery_at: null,
    latest_discovery_status: null,
  },
  safety: {
    unverified_domain_scans_allowed: false,
    default_safe_mode: true,
    workspace_concurrent_scan_limit: 1,
  },
  worker_metrics: {
    active_workers: 0,
    active_jobs: 0,
    queued_jobs: 0,
    failed_jobs: 0,
    avg_job_time: 0,
  },
  scanner_versions: [],
  scanner_metrics: [],
};

export function App() {
  const [token, setToken] = useState<string | null>(() => getStoredToken());

  function handleAuthenticated(payload: AuthPayload) {
    storeToken(payload.token);
    setToken(payload.token);
  }

  function handleLogout() {
    logout().catch(() => clearToken()).finally(() => setToken(null));
  }

  return (
    <Routes>
      <Route path="/" element={<Navigate to={token ? '/dashboard' : '/login'} replace />} />
      <Route path="/login" element={<AuthPage mode="login" onAuthenticated={handleAuthenticated} />} />
      <Route path="/register" element={<AuthPage mode="register" onAuthenticated={handleAuthenticated} />} />
      <Route
        path="/dashboard"
        element={
          <RequireAuth token={token}>
            <Shell onLogout={handleLogout}>
              <DashboardPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/websites"
        element={
          <RequireAuth token={token}>
            <Shell onLogout={handleLogout}>
              <WebsitesPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/websites/new"
        element={
          <RequireAuth token={token}>
            <Shell onLogout={handleLogout}>
              <NewWebsitePage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/websites/:id"
        element={
          <RequireAuth token={token}>
            <Shell onLogout={handleLogout}>
              <WebsiteDetailPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/websites/:id/verification"
        element={
          <RequireAuth token={token}>
            <Shell onLogout={handleLogout}>
              <VerificationPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function RequireAuth({ token, children }: { token: string | null; children: React.ReactNode }) {
  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

function AuthPage({ mode, onAuthenticated }: { mode: 'login' | 'register'; onAuthenticated: (payload: AuthPayload) => void }) {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isRegister = mode === 'register';

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const payload = isRegister ? await register({ name, email, password }) : await login({ email, password });
      onAuthenticated(payload);
      navigate('/dashboard', { replace: true });
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen lg:grid-cols-[1.05fr_0.95fr]">
        <section className="flex items-center px-6 py-10 md:px-12">
          <div className="w-full max-w-md">
            <div className="mb-8 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheck size={20} />
              </div>
              <div>
                <div className="text-sm font-semibold">ScanForge</div>
                <div className="text-xs text-muted-foreground">Verified security audits</div>
              </div>
            </div>

            <h1 className="text-3xl font-semibold tracking-normal">{isRegister ? 'Create account' : 'Welcome back'}</h1>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              {isRegister ? 'Start with a personal workspace and verified assets.' : 'Continue to your security workspace.'}
            </p>

            <form onSubmit={submit} className="mt-8 space-y-4">
              {isRegister ? (
                <label className="form-field">
                  <span>Name</span>
                  <input value={name} onChange={(event) => setName(event.target.value)} required autoComplete="name" />
                </label>
              ) : null}
              <label className="form-field">
                <span>Email</span>
                <input value={email} onChange={(event) => setEmail(event.target.value)} required type="email" autoComplete="email" />
              </label>
              <label className="form-field">
                <span>Password</span>
                <input
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  type="password"
                  minLength={8}
                  autoComplete={isRegister ? 'new-password' : 'current-password'}
                />
              </label>

              {error ? <div className="error-banner">{error}</div> : null}

              <button className="primary-button h-11 w-full justify-center" disabled={submitting}>
                <LockKeyhole size={17} />
                <span>{submitting ? 'Submitting' : isRegister ? 'Create Account' : 'Log In'}</span>
              </button>
            </form>

            <div className="mt-5 text-sm text-muted-foreground">
              {isRegister ? 'Already have an account?' : 'New to ScanForge?'}{' '}
              <Link className="text-primary" to={isRegister ? '/login' : '/register'}>
                {isRegister ? 'Log in' : 'Create one'}
              </Link>
            </div>
          </div>
        </section>
        <section className="hidden border-l border-border bg-surface p-8 lg:block">
          <div className="grid h-full grid-rows-[auto_1fr_auto]">
            <div className="flex justify-end">
              <span className="rounded-md border border-border px-3 py-2 text-xs text-muted-foreground">Phase 03</span>
            </div>
            <div className="flex items-center">
              <div className="w-full">
                <div className="grid gap-4">
                  <MetricCard icon={Globe2} label="Verified Assets" value="0" detail="Workspace ready" />
                  <MetricCard icon={ShieldEllipsis} label="Safety Gate" value="On" detail="Verified targets only" />
                  <MetricCard icon={Radar} label="Scanner Mode" value="Mock" detail="No external tools" />
                </div>
              </div>
            </div>
            <div className="text-xs leading-6 text-muted-foreground">Tokens, credentials and audit metadata stay out of client-visible logs.</div>
          </div>
        </section>
      </div>
    </main>
  );
}

function Shell({ children, onLogout }: { children: React.ReactNode; onLogout: () => void }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-border bg-surface lg:block">
        <div className="flex h-16 items-center gap-3 border-b border-border px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="text-sm font-semibold">ScanForge</div>
            <div className="text-xs text-muted-foreground">Verified security audits</div>
          </div>
        </div>
        <nav className="space-y-1 px-3 py-4">
          {navigation.map((item) => (
            <Link key={item.label} to={item.to} className="nav-item">
              <item.icon size={17} />
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>
      </aside>

      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur md:px-8">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <ShieldEllipsis size={14} />
              <span>ScanForge Console</span>
            </div>
            <h1 className="truncate text-lg font-semibold">Security Workspace</h1>
          </div>
          <div className="flex items-center gap-3">
            <Link className="primary-button" to="/websites/new">
              <Plus size={16} />
              <span>Add Website</span>
            </Link>
            <button className="icon-button" onClick={onLogout} aria-label="Log out">
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <div className="space-y-6 px-4 py-6 md:px-8">{children}</div>
      </main>
    </div>
  );
}

function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary>(fallbackSummary);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    Promise.all([fetchDashboardSummary(), fetchHealth()])
      .then(([dashboardSummary, healthStatus]) => {
        if (!mounted) return;
        setSummary(dashboardSummary);
        setHealth(healthStatus);
      })
      .catch((error: unknown) => {
        if (!mounted) return;
        setApiError(readError(error));
      });

    return () => {
      mounted = false;
    };
  }, []);

  const scoreLabel = useMemo(() => {
    if (summary.risk.average_score === 0 && summary.totals.scans === 0) return 'Awaiting first scan';
    if (summary.risk.average_score >= 70) return 'Needs attention';
    if (summary.risk.average_score >= 40) return 'Watchlist';
    return 'Controlled';
  }, [summary.risk.average_score, summary.totals.scans]);

  const dependencyState = health?.status === 'ok' ? 'Operational' : health ? 'Degraded' : 'Checking';

  return (
    <>
      {apiError ? <div className="error-banner">{apiError}</div> : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={Globe2} label="Total Websites" value={summary.totals.websites.toString()} detail={`${summary.totals.verified_websites} verified`} />
        <MetricCard icon={Gauge} label="Average Finding Risk" value={summary.totals.open_findings === 0 ? '--' : summary.risk.average_score.toString()} detail={scoreLabel} />
        <MetricCard icon={AlertTriangle} label="Open Findings" value={summary.totals.open_findings.toString()} detail={`${summary.risk.critical_findings} critical, ${summary.risk.high_findings} high`} />
        <MetricCard icon={Activity} label="Last Discovery" value={summary.activity.latest_discovery_status ?? '--'} detail={summary.activity.last_discovery_at ? new Date(summary.activity.last_discovery_at).toLocaleString() : 'No discovery yet'} />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.4fr_0.9fr]">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Website Health</h2>
              <p>Workspace quota: {summary.workspace?.scans_used_this_month ?? 0}/{summary.workspace?.monthly_scan_limit ?? 100} scans</p>
            </div>
            <Link className="primary-button" to="/websites">
              <Globe2 size={16} />
              <span>Open Websites</span>
            </Link>
          </div>
          <div className="empty-state">
            <div className="empty-icon">
              <ShieldCheck size={24} />
            </div>
            <div>
              <h3>{summary.totals.websites === 0 ? 'No websites registered' : `${summary.totals.websites} websites registered`}</h3>
              <p>{summary.totals.verified_websites} verified assets are eligible for scan requests.</p>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Safety Controls</h2>
              <p>{dependencyState}</p>
            </div>
          </div>
          <div className="space-y-3">
            <SafetyRow label="Unverified scans" value={summary.safety.unverified_domain_scans_allowed ? 'Allowed' : 'Blocked'} good={!summary.safety.unverified_domain_scans_allowed} />
            <SafetyRow label="Safe mode" value={summary.safety.default_safe_mode ? 'Enabled' : 'Disabled'} good={summary.safety.default_safe_mode} />
            <SafetyRow label="Concurrent scans" value={summary.safety.workspace_concurrent_scan_limit.toString()} good />
            <SafetyRow label="Active workers" value={(summary.worker_metrics?.active_workers ?? 0).toString()} good />
            <SafetyRow label="Active jobs" value={(summary.worker_metrics?.active_jobs ?? 0).toString()} good />
            <SafetyRow label="Queued jobs" value={(summary.worker_metrics?.queued_jobs ?? 0).toString()} good />
            <SafetyRow label="Scanner versions" value={(summary.scanner_versions?.length ?? 0).toString()} good />
            <SafetyRow label="Scanner runs" value={(summary.scanner_metrics ?? []).reduce((total, metric) => total + metric.runs, 0).toString()} good />
            <SafetyRow label="Schema" value={summary.schema_ready ? 'Ready' : 'Awaiting migration'} good={summary.schema_ready} />
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Risk Rollup</h2>
            <p>{summary.risk.top_risky_websites?.length ? `${summary.risk.top_risky_websites.length} websites ranked by finding risk` : 'No website risk yet'}</p>
          </div>
        </div>
        <div className="table-list">
          {(summary.risk.top_risky_websites ?? []).map((website) => (
            <Link className="table-row" key={website.id} to={`/websites/${website.id}`}>
              <div className="min-w-0">
                <div className="truncate font-medium">{website.host}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <span>{website.critical_count} critical</span>
                  <span>{website.high_count} high</span>
                  <span>{website.trend}</span>
                </div>
              </div>
              <RiskBadge score={Math.round(website.risk_score ?? 0)} priority={(website.risk_score ?? 0) >= 85 ? 'critical' : (website.risk_score ?? 0) >= 70 ? 'high' : 'medium'} />
              <ChevronRight className="text-muted-foreground" size={18} />
            </Link>
          ))}
          {summary.risk.top_risky_websites?.length === 0 ? <div className="px-4 py-4 text-sm text-muted-foreground">Findings will populate this rollup after scans or discovery.</div> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Scanner Engines</h2>
            <p>{summary.scanner_versions?.length ? `${summary.scanner_versions.length} tracked adapters` : 'No scanner runs recorded'}</p>
          </div>
        </div>
        <div className="table-list">
          {(summary.scanner_versions ?? []).map((version) => {
            const metric = summary.scanner_metrics?.find((item) => item.scanner_key === version.scanner_key);

            return (
              <div className="table-row" key={version.scanner_key}>
                <div className="min-w-0">
                  <div className="truncate font-medium">{version.scanner_key}</div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">
                    {version.binary_version ?? 'binary unknown'} / {version.templates_version ?? 'templates unknown'}
                  </div>
                </div>
                <StatusBadge status={version.status} />
                <span className="text-xs text-muted-foreground">{metric ? `${metric.success}/${metric.runs} ok` : 'No runs'}</span>
              </div>
            );
          })}
          {summary.scanner_versions?.length === 0 ? <div className="px-4 py-4 text-sm text-muted-foreground">Scanner versions appear after the first adapter check.</div> : null}
        </div>
      </section>
    </>
  );
}

function WebsitesPage() {
  const [websites, setWebsites] = useState<Website[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchWebsites()
      .then(setWebsites)
      .catch((apiError) => setError(readError(apiError)))
      .finally(() => setLoading(false));
  }, []);

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Websites</h2>
          <p>{loading ? 'Loading' : `${websites.length} registered assets`}</p>
        </div>
        <Link className="primary-button" to="/websites/new">
          <Plus size={16} />
          <span>Add Website</span>
        </Link>
      </div>

      {error ? <div className="error-banner">{error}</div> : null}

      {websites.length === 0 && !loading ? (
        <div className="empty-state">
          <div className="empty-icon">
            <Globe2 size={24} />
          </div>
          <div>
            <h3>No websites registered</h3>
            <p>Add a website to start ownership verification.</p>
          </div>
        </div>
      ) : (
        <div className="table-list">
          {websites.map((website) => (
            <Link key={website.id} to={`/websites/${website.id}`} className="table-row">
              <div className="min-w-0">
                <div className="truncate font-medium">{website.host}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <span>{website.environment}</span>
                  <span>{website.importance}</span>
                  <span>{website.last_scan_at ? `Last scan ${new Date(website.last_scan_at).toLocaleDateString()}` : 'No scans yet'}</span>
                </div>
              </div>
              <StatusBadge status={website.verification_status} />
              <ChevronRight className="text-muted-foreground" size={18} />
            </Link>
          ))}
        </div>
      )}
    </section>
  );
}

function WebsiteDetailPage() {
  const { id } = useParams();
  const [website, setWebsite] = useState<Website | null>(null);
  const [summary, setSummary] = useState<AssetSummary | null>(null);
  const [technologySummary, setTechnologySummary] = useState<TechnologySummary | null>(null);
  const [technologyGraph, setTechnologyGraph] = useState<TechnologyGraph | null>(null);
  const [scanPlans, setScanPlans] = useState<ScanPlan[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [discoveries, setDiscoveries] = useState<AssetDiscovery[]>([]);
  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [findingSummary, setFindingSummary] = useState<FindingSummary | null>(null);
  const [findingFilters, setFindingFilters] = useState<FindingFilters>({});
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [findingActionId, setFindingActionId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [fingerprinting, setFingerprinting] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [scanStarting, setScanStarting] = useState(false);
  const [scanActionId, setScanActionId] = useState<number | null>(null);
  const [scanConsent, setScanConsent] = useState(false);
  const [scanType, setScanType] = useState<'passive' | 'standard' | 'deep' | 'authenticated'>('standard');
  const [safetyMode, setSafetyMode] = useState<'safe' | 'standard' | 'deep' | 'authenticated'>('standard');
  const [selectedScanPlanId, setSelectedScanPlanId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function refreshFindings(filters = findingFilters) {
    if (!id) return;

    try {
      const [findingList, findingSummaryData] = await Promise.all([
        fetchFindings(id, filters),
        fetchFindingSummary(id),
      ]);
      setFindings(findingList.data);
      setFindingSummary(findingSummaryData);
    } catch (apiError) {
      setError(readError(apiError));
    }
  }

  async function load() {
    if (!id) return;

    setLoading(true);
    setError(null);

    try {
      const [websiteData, summaryData, discoveryData, technologyData, graphData, planData, scanData] = await Promise.all([
        fetchWebsite(id),
        fetchAssetSummary(id),
        fetchDiscoveries(id),
        fetchTechnologySummary(id),
        fetchTechnologyGraph(id),
        fetchScanPlans(id),
        fetchScans(id),
      ]);
      const scansForState = scanData[0] ? [await fetchScan(id, scanData[0].id), ...scanData.slice(1)] : scanData;
      setWebsite(websiteData);
      setSummary(summaryData);
      setDiscoveries(discoveryData);
      setTechnologySummary(technologyData);
      setTechnologyGraph(graphData);
      setScanPlans(planData);
      setScans(scansForState);
      setSelectedScanPlanId((current) => current ?? planData[0]?.id ?? null);
      await refreshFindings();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [id]);

  useEffect(() => {
    refreshFindings();
  }, [id, findingFilters.severity, findingFilters.priority, findingFilters.status, findingFilters.scanner_key, findingFilters.cve, findingFilters.search]);

  async function handleRunDiscovery() {
    if (!id) return;

    setRunning(true);
    setError(null);
    setMessage(null);

    try {
      const discovery = await runDiscovery(id);
      setMessage(`Discovery ${discovery.status}`);
      await load();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setRunning(false);
    }
  }

  async function handleRunFingerprint() {
    if (!id) return;

    setFingerprinting(true);
    setError(null);
    setMessage(null);

    try {
      const result = await runFingerprint(id);
      setTechnologySummary(result);
      setMessage(`Fingerprint coverage ${result.coverage.percentage}%`);
      const graph = await fetchTechnologyGraph(id);
      setTechnologyGraph(graph);
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setFingerprinting(false);
    }
  }

  async function handleGeneratePlan() {
    if (!id) return;

    setPlanning(true);
    setError(null);
    setMessage(null);

    try {
      const plan = await generateScanPlan(id);
      setScanPlans([plan, ...scanPlans.filter((item) => item.id !== plan.id)]);
      setSelectedScanPlanId(plan.id);
      setMessage(`Scan plan coverage ${plan.coverage_prediction}%`);
      const graph = await fetchTechnologyGraph(id);
      setTechnologyGraph(graph);
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setPlanning(false);
    }
  }

  async function handleStartScan() {
    if (!id) return;

    const planId = selectedScanPlanId ?? scanPlans[0]?.id;

    if (!planId) {
      setError('A ready scan plan is required before starting a scan.');
      return;
    }

    setScanStarting(true);
    setError(null);
    setMessage(null);

    try {
      const scan = await startScan(id, {
        scan_type: scanType,
        safety_mode: safetyMode,
        scan_plan_id: planId,
        consent_accepted: scanConsent,
      });
      setScans([scan, ...scans.filter((item) => item.id !== scan.id)]);
      setMessage(`Scan ${scan.status}`);
      await load();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setScanStarting(false);
    }
  }

  async function handleCancelScan(scanId: number) {
    if (!id) return;

    setScanActionId(scanId);
    setError(null);
    setMessage(null);

    try {
      const scan = await cancelScan(id, scanId);
      setScans([scan, ...scans.filter((item) => item.id !== scan.id)]);
      setMessage(`Scan ${scan.status}`);
      await load();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setScanActionId(null);
    }
  }

  async function handleRetryFailedScan(scanId: number) {
    if (!id) return;

    setScanActionId(scanId);
    setError(null);
    setMessage(null);

    try {
      const scan = await retryFailedScan(id, scanId);
      setScans([scan, ...scans.filter((item) => item.id !== scan.id)]);
      setMessage(`Scan ${scan.status}`);
      await load();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setScanActionId(null);
    }
  }

  async function handleSelectFinding(findingId: number) {
    if (!id) return;

    setError(null);

    try {
      setSelectedFinding(await fetchFinding(id, findingId));
    } catch (apiError) {
      setError(readError(apiError));
    }
  }

  async function handleFindingStatus(status: string, createRule = false) {
    if (!id || !selectedFinding) return;

    setFindingActionId(selectedFinding.id);
    setError(null);
    setMessage(null);

    try {
      const updated = await updateFindingStatus(id, selectedFinding.id, {
        status,
        create_rule: createRule,
        reason: createRule ? `Marked ${status} and saved as a suppression rule.` : `Marked ${status} from the findings panel.`,
      });
      setSelectedFinding(updated);
      setMessage(`Finding ${updated.status}`);
      await refreshFindings();
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setFindingActionId(null);
    }
  }

  const verified = website?.verification_status === 'verified';
  const latestScan = scans[0];
  const activeScan = scans.find((scan) => !['completed', 'cancelled', 'failed', 'timeout'].includes(scan.status));

  return (
    <section className="space-y-4">
      <div className="panel">
        <div className="panel-heading">
          <div>
            <h2>{website?.host ?? 'Website Detail'}</h2>
            <p>{loading ? 'Loading asset profile' : `${website?.environment ?? ''} asset profile`}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {!verified && website ? (
              <Link className="primary-button" to={`/websites/${website.id}/verification`}>
                <ShieldCheck size={16} />
                <span>Verify</span>
              </Link>
            ) : null}
            <button className="primary-button" onClick={handleRunDiscovery} disabled={!verified || running || !website}>
              <Radar size={16} />
              <span>{running ? 'Running' : 'Run Discovery'}</span>
            </button>
            <button className="primary-button" onClick={handleRunFingerprint} disabled={!verified || fingerprinting || !website}>
              <Fingerprint size={16} />
              <span>{fingerprinting ? 'Fingerprinting' : 'Fingerprint'}</span>
            </button>
            <button className="primary-button" onClick={handleGeneratePlan} disabled={!verified || planning || !website}>
              <GitBranch size={16} />
              <span>{planning ? 'Planning' : 'Plan Scan'}</span>
            </button>
          </div>
        </div>

        {error ? <div className="error-banner">{error}</div> : null}
        {message ? <div className="success-banner">{message}</div> : null}

        {!verified && website ? (
          <div className="error-banner">Discovery is available after domain ownership verification.</div>
        ) : null}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <MetricCard icon={Gauge} label="Discovery Score" value={summary?.last_discovery?.discovery_score?.toString() ?? '--'} detail={summary?.last_discovery?.status ?? 'No discovery'} />
          <MetricCard icon={Fingerprint} label="Technology Coverage" value={technologySummary?.coverage.percentage !== undefined ? `${technologySummary.coverage.percentage}%` : '--'} detail={`${technologySummary?.technologies.length ?? 0} fingerprints`} />
          <MetricCard icon={Globe2} label="IP Addresses" value={(summary?.ip_addresses.length ?? 0).toString()} detail={`${summary?.subdomain_count ?? 0} subdomains`} />
          <MetricCard icon={Server} label="HTTP" value={summary?.http?.status_code?.toString() ?? '--'} detail={summary?.http?.server ?? 'No observation'} />
          <MetricCard icon={AlertTriangle} label="Passive Findings" value={(summary?.passive_findings.length ?? 0).toString()} detail={`${technologySummary?.conflicts.length ?? 0} conflicts`} />
        </div>
      </div>

      <FindingsPanel
        findings={findings}
        summary={findingSummary}
        filters={findingFilters}
        onFiltersChange={setFindingFilters}
        onSelect={handleSelectFinding}
      />

      <div className="grid gap-4 xl:grid-cols-4">
        <AssetCard title="DNS" value={formatRecordCounts(summary?.dns_record_counts)} />
        <AssetCard title="IP / Hosting" value={summary?.ip_addresses.map((ip) => `${ip.ip}${ip.provider ? ` (${ip.provider})` : ''}`).join(', ') || 'No IPs'} />
        <AssetCard title="SSL" value={summary?.ssl ? `${summary.ssl.available ? 'Available' : 'Unavailable'}${summary.ssl.days_remaining !== null ? `, ${summary.ssl.days_remaining} days` : ''}` : 'No certificate'} />
        <AssetCard title="Headers" value={formatSecurityHeaders(summary)} />
        <AssetCard title="Cookies" value={summary?.cookies ? `${summary.cookies.total} total, ${summary.cookies.secure} Secure, ${summary.cookies.http_only} HttpOnly` : 'No cookies'} />
        <AssetCard title="WHOIS" value={summary?.whois ? `${summary.whois.status ?? 'unknown'}${summary.whois.age_days ? `, ${summary.whois.age_days} days old` : ''}` : 'Unavailable'} />
        <AssetCard title="robots.txt" value={summary?.robots ? `${summary.robots.available ? 'Available' : 'Missing'}${summary.robots.sensitive_paths.length ? `, ${summary.robots.sensitive_paths.length} sensitive hints` : ''}` : 'Unknown'} />
        <AssetCard title="sitemap.xml" value={summary?.sitemap ? (summary.sitemap.available ? 'Available' : 'Missing') : 'Unknown'} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Discovery History</h2>
              <p>{discoveries.length} runs</p>
            </div>
          </div>
          <div className="table-list">
            {discoveries.length === 0 ? (
              <div className="px-4 py-4 text-sm text-muted-foreground">No discovery runs yet.</div>
            ) : (
              discoveries.map((discovery) => (
                <div className="table-row" key={discovery.id}>
                  <div>
                    <div className="font-medium">Discovery #{discovery.id}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{discovery.completed_at ? new Date(discovery.completed_at).toLocaleString() : 'Not completed'}</div>
                  </div>
                  <StatusBadge status={discovery.status} />
                  <span className="text-sm font-medium">{discovery.discovery_score ?? '--'}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Passive Findings</h2>
              <p>Generated without exploit or brute force checks</p>
            </div>
          </div>
          <div className="space-y-3">
            {summary?.passive_findings.length ? (
              summary.passive_findings.map((finding) => (
                <div className="flex items-center justify-between rounded-lg border border-border bg-background px-3 py-3" key={finding.id}>
                  <div className="text-sm">{finding.title}</div>
                  <StatusBadge status={finding.severity} />
                </div>
              ))
            ) : (
              <div className="text-sm text-muted-foreground">No passive findings yet.</div>
            )}
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Technology Tree</h2>
              <p>{technologySummary?.technologies.length ?? 0} fingerprints, {technologySummary?.relationships.length ?? 0} relationships</p>
            </div>
            <StatusBadge status={technologySummary?.coverage.percentage !== undefined ? `${technologySummary.coverage.percentage}%` : 'pending'} />
          </div>
          <TechnologyTree technologies={technologySummary?.technologies ?? []} relationships={technologySummary?.relationships ?? []} />
        </div>

        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Scan Plan</h2>
              <p>{scanPlans[0] ? `${scanPlans[0].items.length} recommended modules` : 'No plan generated'}</p>
            </div>
            {scanPlans[0] ? <StatusBadge status={`${scanPlans[0].coverage_prediction}%`} /> : null}
          </div>
          {scanPlans[0] ? (
            <div className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <SafetyRow label="Safe mode" value={scanPlans[0].safe_mode ? 'Enabled' : 'Disabled'} good={scanPlans[0].safe_mode} />
                <SafetyRow label="Requests" value={scanPlans[0].estimated_requests.toString()} good />
                <SafetyRow label="Runtime" value={`${scanPlans[0].estimated_runtime_seconds}s`} good />
                <SafetyRow label="Memory" value={`${scanPlans[0].estimated_memory_mb} MB`} good />
              </div>
              <div className="table-list">
                {scanPlans[0].items.slice(0, 5).map((item) => (
                  <div className="table-row" key={item.id}>
                    <div className="min-w-0">
                      <div className="truncate font-medium">{item.scanner_key} / {item.scan_module}</div>
                      <div className="mt-1 truncate text-xs text-muted-foreground">{`${item.technology_key} -> ${item.template_group}`}</div>
                    </div>
                    <StatusBadge status={`${item.recommendation_score}`} />
                    <span className="text-xs text-muted-foreground">{item.estimated_requests} req</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">No scan plan yet.</div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-heading">
          <div>
            <h2>Scans</h2>
            <p>{latestScan ? `Latest scan ${latestScan.status}` : 'No scans queued'}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {activeScan ? (
              <button className="primary-button" onClick={() => handleCancelScan(activeScan.id)} disabled={scanActionId === activeScan.id}>
                <XCircle size={16} />
                <span>{scanActionId === activeScan.id ? 'Cancelling' : 'Cancel'}</span>
              </button>
            ) : null}
            {latestScan && ['failed', 'timeout'].includes(latestScan.status) ? (
              <button className="primary-button" onClick={() => handleRetryFailedScan(latestScan.id)} disabled={scanActionId === latestScan.id}>
                <RotateCcw size={16} />
                <span>{scanActionId === latestScan.id ? 'Retrying' : 'Retry Failed'}</span>
              </button>
            ) : null}
          </div>
        </div>

        <div className="grid gap-4 xl:grid-cols-[0.8fr_1.2fr]">
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="form-field">
                <span>Scan Plan</span>
                <select value={selectedScanPlanId ?? scanPlans[0]?.id ?? ''} onChange={(event) => setSelectedScanPlanId(Number(event.target.value) || null)} disabled={!scanPlans.length}>
                  {scanPlans.length ? (
                    scanPlans.map((plan) => (
                      <option key={plan.id} value={plan.id}>
                        Plan #{plan.id} - {plan.items.length} jobs
                      </option>
                    ))
                  ) : (
                    <option value="">No plan</option>
                  )}
                </select>
              </label>
              <label className="form-field">
                <span>Scan Type</span>
                <select value={scanType} onChange={(event) => setScanType(event.target.value as typeof scanType)}>
                  <option value="passive">Passive</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                  <option value="authenticated">Authenticated</option>
                </select>
              </label>
              <label className="form-field">
                <span>Safety Mode</span>
                <select value={safetyMode} onChange={(event) => setSafetyMode(event.target.value as typeof safetyMode)}>
                  <option value="safe">Safe</option>
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                  <option value="authenticated">Authenticated</option>
                </select>
              </label>
              <div className="flex items-end">
                <button className="primary-button h-10 w-full justify-center" onClick={handleStartScan} disabled={!verified || !scanConsent || !scanPlans.length || scanStarting || Boolean(activeScan)}>
                  <Search size={16} />
                  <span>{scanStarting ? 'Starting' : 'Start Scan'}</span>
                </button>
              </div>
            </div>
            <label className="flex items-start gap-3 rounded-lg border border-border bg-background p-3 text-sm">
              <input className="mt-1" type="checkbox" checked={scanConsent} onChange={(event) => setScanConsent(event.target.checked)} />
              <span>I confirm I own or am authorized to test this website.</span>
            </label>
            {latestScan ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <SafetyRow label="Safety mode" value={latestScan.safety_mode} good={latestScan.safety_mode === 'safe' || latestScan.safety_mode === 'standard'} />
                <SafetyRow label="Artifacts" value={latestScan.artifacts_count.toString()} good />
                <SafetyRow label="Requests" value={(latestScan.request_budget ?? 0).toString()} good />
                <SafetyRow label="Jobs" value={`${latestScan.completed_jobs}/${latestScan.total_jobs}`} good={latestScan.failed_jobs === 0} />
              </div>
            ) : null}
          </div>

          <div className="space-y-4">
            {latestScan ? (
              <>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium">Scan #{latestScan.id}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{latestScan.created_at ? new Date(latestScan.created_at).toLocaleString() : 'Queued'}</div>
                  </div>
                  <StatusBadge status={latestScan.status} />
                </div>
                <div className="h-3 overflow-hidden rounded-md border border-border bg-background">
                  <div className="h-full bg-primary transition-all" style={{ width: `${Math.min(100, latestScan.progress_percent)}%` }} />
                </div>
                <div className="table-list">
                  {(latestScan.jobs ?? []).slice(0, 8).map((job) => (
                    <div className="table-row" key={job.id}>
                      <div className="min-w-0">
                        <div className="truncate font-medium">{job.scanner_key ?? 'mock'} / {job.scan_module ?? 'mock'}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{job.template_group ?? job.plan_item?.technology_key ?? job.queue_name} - {job.progress_percent}%</div>
                      </div>
                      <StatusBadge status={job.status} />
                      <span className="text-xs text-muted-foreground">{job.request_count} req</span>
                    </div>
                  ))}
                  {latestScan.jobs?.length === 0 ? <div className="px-4 py-4 text-sm text-muted-foreground">No jobs queued.</div> : null}
                </div>
                <div className="space-y-2">
                  <div className="text-xs font-medium uppercase text-muted-foreground">Findings</div>
                  {latestScan.recent_findings.length ? (
                    latestScan.recent_findings.map((finding) => (
                      <div className="flex items-center gap-3 rounded-lg border border-border bg-background px-3 py-3" key={finding.id}>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium">{finding.title}</div>
                          <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                            <span>{finding.scanner_key ?? 'scanner'}</span>
                            {finding.template_id ? <span>{finding.template_id}</span> : null}
                            <span className="truncate">{finding.affected_url}</span>
                          </div>
                        </div>
                        <StatusBadge status={finding.severity} />
                        {finding.has_raw_evidence ? <span className="status-badge status-good">Raw evidence available</span> : null}
                      </div>
                    ))
                  ) : (
                    <div className="rounded-lg border border-border bg-background px-3 py-4 text-sm text-muted-foreground">No findings reported for this scan.</div>
                  )}
                </div>
              </>
            ) : (
              <div className="empty-state min-h-64">
                <div className="empty-icon">
                  <Search size={24} />
                </div>
                <div>
                  <h3>No scans yet</h3>
                  <p>Awaiting first queued scan.</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {technologySummary?.conflicts.length ? (
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Fingerprint Conflicts</h2>
              <p>{technologySummary.conflicts.length} active conflicts</p>
            </div>
          </div>
          <div className="space-y-3">
            {technologySummary.conflicts.map((conflict) => (
              <div className="error-banner" key={conflict.reason}>{conflict.reason}</div>
            ))}
          </div>
        </div>
      ) : null}

      <div className="panel">
        <div className="panel-heading">
          <div>
            <h2>Technology Hints</h2>
            <p>Rule engine evidence from passive observations</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {technologySummary?.technologies.length ? (
            technologySummary.technologies.map((technology) => (
              <span className="status-badge status-pending" key={technology.technology_key}>
                {technology.name} {technology.confidence_score}/{technology.quality_score}
              </span>
            ))
          ) : (
            <span className="text-sm text-muted-foreground">No technology hints yet.</span>
          )}
        </div>
      </div>

      {technologyGraph ? (
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>AI Graph Export</h2>
              <p>{technologyGraph.technologies.length} nodes ready</p>
            </div>
            <StatusBadge status={technologyGraph.latest_scan_plan ? 'planned' : 'pending'} />
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <AssetCard title="Host" value={technologyGraph.asset_graph.host} />
            <AssetCard title="SSL" value={technologyGraph.asset_graph.ssl.available ? `${technologyGraph.asset_graph.ssl.issuer ?? 'Available'}` : 'Unavailable'} />
            <AssetCard title="Scan Plan" value={technologyGraph.latest_scan_plan ? `${technologyGraph.latest_scan_plan.items} items, ${technologyGraph.latest_scan_plan.coverage_prediction}% coverage` : 'No plan'} />
          </div>
        </div>
      ) : null}

      {selectedFinding ? (
        <FindingDrawer
          finding={selectedFinding}
          busy={findingActionId === selectedFinding.id}
          onClose={() => setSelectedFinding(null)}
          onStatus={handleFindingStatus}
        />
      ) : null}
    </section>
  );
}

function FindingsPanel({
  findings,
  summary,
  filters,
  onFiltersChange,
  onSelect,
}: {
  findings: FindingListItem[];
  summary: FindingSummary | null;
  filters: FindingFilters;
  onFiltersChange: React.Dispatch<React.SetStateAction<FindingFilters>>;
  onSelect: (findingId: number) => void;
}) {
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <h2>Findings</h2>
          <p>{summary ? `${summary.open} open, average risk ${summary.average_risk_score}` : 'Loading normalized findings'}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(summary?.severity ?? {}).map(([severity, count]) => (
            <span className="status-badge status-pending" key={severity}>{severity} {count}</span>
          ))}
        </div>
      </div>

      <div className="mb-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <label className="form-field xl:col-span-2">
          <span>Search</span>
          <input value={filters.search ?? ''} onChange={(event) => onFiltersChange((current) => ({ ...current, search: event.target.value || undefined }))} />
        </label>
        <FilterSelect label="Severity" value={filters.severity} values={['critical', 'high', 'medium', 'low', 'info']} onChange={(value) => onFiltersChange((current) => ({ ...current, severity: value }))} />
        <FilterSelect label="Priority" value={filters.priority} values={['critical', 'high', 'medium', 'low', 'info']} onChange={(value) => onFiltersChange((current) => ({ ...current, priority: value }))} />
        <FilterSelect label="Status" value={filters.status} values={['new', 'confirmed', 'reopened', 'ignored', 'resolved', 'false_positive']} onChange={(value) => onFiltersChange((current) => ({ ...current, status: value }))} />
        <label className="form-field">
          <span>CVE</span>
          <input value={filters.cve ?? ''} onChange={(event) => onFiltersChange((current) => ({ ...current, cve: event.target.value || undefined }))} />
        </label>
      </div>

      <div className="table-list">
        {findings.length ? (
          findings.map((finding) => (
            <button className="table-row text-left" key={finding.id} onClick={() => onSelect(finding.id)}>
              <div className="min-w-0">
                <div className="truncate font-medium">{finding.title}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <span>{finding.taxonomy?.category ?? 'Unclassified'}</span>
                  <span>{finding.asset_type ?? 'asset'}: {finding.asset_identifier ?? finding.affected_component ?? finding.affected_url}</span>
                  <span>{finding.occurrence_count} occurrences</span>
                  <span>correlation {finding.correlation_score}</span>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {finding.sources.slice(0, 4).map((source, index) => (
                    <span className="status-badge status-pending" key={`${source.scanner_key}-${index}`}>{source.scanner_key}</span>
                  ))}
                </div>
              </div>
              <RiskBadge score={finding.risk_score} priority={finding.priority} />
              <StatusBadge status={finding.status} />
            </button>
          ))
        ) : (
          <div className="px-4 py-4 text-sm text-muted-foreground">No findings match the current filters.</div>
        )}
      </div>
    </div>
  );
}

function FilterSelect({ label, value, values, onChange }: { label: string; value?: string; values: string[]; onChange: (value: string | undefined) => void }) {
  return (
    <label className="form-field">
      <span>{label}</span>
      <select value={value ?? ''} onChange={(event) => onChange(event.target.value || undefined)}>
        <option value="">All</option>
        {values.map((item) => (
          <option value={item} key={item}>{item}</option>
        ))}
      </select>
    </label>
  );
}

function FindingDrawer({ finding, busy, onClose, onStatus }: { finding: FindingDetail; busy: boolean; onClose: () => void; onStatus: (status: string, createRule?: boolean) => void }) {
  return (
    <div className="fixed inset-y-0 right-0 z-20 w-full max-w-2xl overflow-y-auto border-l border-border bg-surface p-5 shadow-soft">
      <div className="mb-5 flex items-start justify-between gap-4 border-b border-border pb-4">
        <div className="min-w-0">
          <h2 className="truncate text-base font-semibold">{finding.title}</h2>
          <div className="mt-2 flex flex-wrap gap-2">
            <RiskBadge score={finding.risk_score} priority={finding.priority} />
            <StatusBadge status={finding.status} />
            <span className="status-badge status-pending">confidence {finding.confidence_score}</span>
          </div>
        </div>
        <button className="icon-button" onClick={onClose} aria-label="Close finding detail">
          <XCircle size={17} />
        </button>
      </div>

      <div className="space-y-5">
        <section>
          <div className="text-xs font-medium uppercase text-muted-foreground">Taxonomy</div>
          <div className="mt-2 flex flex-wrap gap-2">
            <span className="status-badge status-pending">{finding.taxonomy?.category ?? 'Unclassified'}</span>
            {finding.taxonomy?.subcategory ? <span className="status-badge status-pending">{finding.taxonomy.subcategory}</span> : null}
            {finding.taxonomy?.owasp_category ? <span className="status-badge status-pending">{finding.taxonomy.owasp_category}</span> : null}
            {finding.taxonomy?.cwe ? <span className="status-badge status-pending">{finding.taxonomy.cwe}</span> : null}
            {finding.taxonomy?.capec ? <span className="status-badge status-pending">{finding.taxonomy.capec}</span> : null}
          </div>
        </section>

        <section className="grid gap-3 sm:grid-cols-2">
          <SafetyRow label="Asset" value={finding.asset_identifier ?? finding.affected_url} good />
          <SafetyRow label="Sources" value={finding.sources.map((source) => source.scanner_key).join(', ') || finding.scanner_key || 'unknown'} good />
          <SafetyRow label="Occurrences" value={finding.occurrence_count.toString()} good />
          <SafetyRow label="SLA" value={finding.sla_due_at ? new Date(finding.sla_due_at).toLocaleDateString() : 'None'} good={finding.priority === 'info' || finding.priority === 'low'} />
        </section>

        {finding.description ? (
          <section>
            <div className="text-xs font-medium uppercase text-muted-foreground">Description</div>
            <p className="mt-2 text-sm leading-6">{finding.description}</p>
          </section>
        ) : null}

        <section>
          <div className="text-xs font-medium uppercase text-muted-foreground">Evidence</div>
          <div className="mt-2 space-y-2">
            {finding.evidences.length ? (
              finding.evidences.map((evidence) => (
                <code className="block whitespace-pre-wrap rounded-md border border-border bg-background p-3 text-xs" key={evidence.id}>{evidence.preview ?? evidence.sha256}</code>
              ))
            ) : (
              <code className="block whitespace-pre-wrap rounded-md border border-border bg-background p-3 text-xs">{finding.evidence_text ?? 'No evidence preview.'}</code>
            )}
          </div>
        </section>

        {finding.remediation ? (
          <section>
            <div className="text-xs font-medium uppercase text-muted-foreground">Remediation</div>
            <p className="mt-2 text-sm leading-6">{finding.remediation}</p>
          </section>
        ) : null}

        {finding.references.length ? (
          <section>
            <div className="text-xs font-medium uppercase text-muted-foreground">References</div>
            <div className="mt-2 space-y-2">
              {finding.references.map((reference) => (
                <a className="block break-words text-sm text-primary" href={reference} key={reference} target="_blank" rel="noreferrer">{reference}</a>
              ))}
            </div>
          </section>
        ) : null}

        <section>
          <div className="text-xs font-medium uppercase text-muted-foreground">Actions</div>
          <div className="mt-2 flex flex-wrap gap-2">
            <button className="primary-button" disabled={busy} onClick={() => onStatus('confirmed')}>
              <CheckCircle2 size={16} />
              <span>Confirm</span>
            </button>
            <button className="primary-button" disabled={busy} onClick={() => onStatus('resolved')}>
              <CheckCircle2 size={16} />
              <span>Resolve</span>
            </button>
            <button className="primary-button" disabled={busy} onClick={() => onStatus('ignored', true)}>
              <ShieldEllipsis size={16} />
              <span>Ignore Rule</span>
            </button>
            <button className="primary-button" disabled={busy} onClick={() => onStatus('false_positive', true)}>
              <XCircle size={16} />
              <span>False Positive</span>
            </button>
            <button className="primary-button" disabled={busy} onClick={() => onStatus('reopened')}>
              <RotateCcw size={16} />
              <span>Reopen</span>
            </button>
          </div>
        </section>

        <section>
          <div className="text-xs font-medium uppercase text-muted-foreground">History</div>
          <div className="mt-2 space-y-2">
            {finding.events.slice(0, 6).map((event, index) => (
              <div className="rounded-lg border border-border bg-background px-3 py-2 text-xs" key={`${event.changed_at}-${index}`}>
                {event.old_status ?? 'none'} {'->'} {event.new_status} {event.changed_at ? `at ${new Date(event.changed_at).toLocaleString()}` : ''}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

function TechnologyTree({ technologies, relationships }: { technologies: TechnologySummary['technologies']; relationships: TechnologyRelationship[] }) {
  if (technologies.length === 0) {
    return <div className="text-sm text-muted-foreground">No technology graph yet.</div>;
  }

  const byKey = new Map(technologies.map((technology) => [technology.technology_key, technology]));
  const children = new Map<string, string[]>();
  const childKeys = new Set<string>();

  relationships.forEach((relationship) => {
    if (!byKey.has(relationship.parent) || !byKey.has(relationship.child)) return;
    children.set(relationship.parent, [...(children.get(relationship.parent) ?? []), relationship.child]);
    childKeys.add(relationship.child);
  });

  const roots = technologies
    .filter((technology) => !childKeys.has(technology.technology_key))
    .sort((left, right) => right.confidence_score - left.confidence_score);
  const visibleRoots = roots.length ? roots : technologies.slice(0, 4);

  return (
    <div className="space-y-2">
      {visibleRoots.map((technology) => (
        <TechnologyTreeNode
          key={technology.technology_key}
          technologyKey={technology.technology_key}
          byKey={byKey}
          children={children}
          depth={0}
          visited={new Set()}
        />
      ))}
    </div>
  );
}

function TechnologyTreeNode({
  technologyKey,
  byKey,
  children,
  depth,
  visited,
}: {
  technologyKey: string;
  byKey: Map<string, TechnologySummary['technologies'][number]>;
  children: Map<string, string[]>;
  depth: number;
  visited: Set<string>;
}) {
  const technology = byKey.get(technologyKey);

  if (!technology || visited.has(technologyKey)) {
    return null;
  }

  const nextVisited = new Set(visited);
  nextVisited.add(technologyKey);
  const nodeChildren = (children.get(technologyKey) ?? []).filter((child) => byKey.has(child));

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 rounded-lg border border-border bg-background px-3 py-3" style={{ marginLeft: depth * 18 }}>
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-primary">
          {depth === 0 ? <Globe2 size={16} /> : depth === 1 ? <Server size={16} /> : <Fingerprint size={16} />}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">
            {technology.name}{technology.version ? ` ${technology.version}` : ''}
          </div>
          <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span>{technology.category ?? 'unknown'}</span>
            <span>confidence {technology.confidence_score}</span>
            <span>quality {technology.quality_score}</span>
          </div>
        </div>
        <StatusBadge status={technology.analysis_required ? 'AI' : 'done'} />
      </div>
      {nodeChildren.map((child) => (
        <TechnologyTreeNode key={`${technologyKey}-${child}`} technologyKey={child} byKey={byKey} children={children} depth={depth + 1} visited={nextVisited} />
      ))}
    </div>
  );
}

function NewWebsitePage() {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [environment, setEnvironment] = useState<Website['environment']>('production');
  const [importance, setImportance] = useState<Website['importance']>('normal');
  const [tags, setTags] = useState('production');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      const result = await createWebsite({
        url,
        environment,
        importance,
        notes: notes || undefined,
        tags: tags.split(',').map((tag) => tag.trim()).filter(Boolean),
      });

      navigate(`/websites/${result.website.id}/verification`);
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="panel max-w-3xl">
      <div className="panel-heading">
        <div>
          <h2>Add Website</h2>
          <p>Only verified, public http/https targets can request scans.</p>
        </div>
      </div>
      <form onSubmit={submit} className="grid gap-4">
        <label className="form-field">
          <span>Website URL</span>
          <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com" required />
        </label>
        <div className="grid gap-4 md:grid-cols-2">
          <label className="form-field">
            <span>Environment</span>
            <select value={environment} onChange={(event) => setEnvironment(event.target.value as Website['environment'])}>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="other">Other</option>
            </select>
          </label>
          <label className="form-field">
            <span>Importance</span>
            <select value={importance} onChange={(event) => setImportance(event.target.value as Website['importance'])}>
              <option value="low">Low</option>
              <option value="normal">Normal</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
        </div>
        <label className="form-field">
          <span>Tags</span>
          <input value={tags} onChange={(event) => setTags(event.target.value)} placeholder="production, customer, wordpress" />
        </label>
        <label className="form-field">
          <span>Notes</span>
          <textarea value={notes} onChange={(event) => setNotes(event.target.value)} rows={4} />
        </label>
        {error ? <div className="error-banner">{error}</div> : null}
        <button className="primary-button h-11 justify-center" disabled={submitting}>
          <Globe2 size={17} />
          <span>{submitting ? 'Saving' : 'Save Website'}</span>
        </button>
      </form>
    </section>
  );
}

function VerificationPage() {
  const { id } = useParams();
  const [verification, setVerification] = useState<VerificationPayload | null>(null);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    fetchVerification(id)
      .then(setVerification)
      .catch((apiError) => setError(readError(apiError)));
  }, [id]);

  async function runCheck() {
    if (!id) return;

    setChecking(true);
    setError(null);
    setMessage(null);

    try {
      const result = await checkVerification(id);
      setMessage(result.verified ? `Verified with ${result.verified_method}` : 'Verification pending');
      const refreshed = await fetchVerification(id);
      setVerification(refreshed);
    } catch (apiError) {
      setError(readError(apiError));
    } finally {
      setChecking(false);
    }
  }

  return (
    <section className="space-y-4">
      <div className="panel">
        <div className="panel-heading">
          <div>
            <h2>Domain Verification</h2>
            <p>{verification?.host ?? 'Loading'}</p>
          </div>
          <button className="primary-button" onClick={runCheck} disabled={checking || !verification}>
            <ShieldCheck size={16} />
            <span>{checking ? 'Checking' : 'Check'}</span>
          </button>
        </div>
        {error ? <div className="error-banner">{error}</div> : null}
        {message ? <div className="success-banner">{message}</div> : null}
        {verification ? (
          <div className="token-box">
            <span>{verification.token}</span>
            <button className="icon-button" onClick={() => navigator.clipboard?.writeText(verification.token)} aria-label="Copy token">
              <Copy size={16} />
            </button>
          </div>
        ) : null}
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        {verification?.methods.map((method) => (
          <div key={method.method} className="panel min-h-56">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-background text-primary">
                <ShieldEllipsis size={18} />
              </div>
              <StatusBadge status={method.status} />
            </div>
            <h2>{method.label}</h2>
            <div className="mt-4 space-y-3 text-sm">
              {method.record_value ? <CodeLine label="TXT" value={method.record_value} /> : null}
              {method.path ? <CodeLine label="Path" value={method.path} /> : null}
              {method.expected_body ? <CodeLine label="Body" value={method.expected_body} /> : null}
              {method.tag ? <CodeLine label="Meta" value={method.tag} /> : null}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

type IconComponent = React.ComponentType<{ size?: number; className?: string }>;

function MetricCard({ icon: Icon, label, value, detail }: { icon: IconComponent; label: string; value: string; detail: string }) {
  return (
    <div className="metric-card">
      <div className="metric-icon">
        <Icon size={19} />
      </div>
      <div>
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="mt-2 text-3xl font-semibold tracking-normal">{value}</div>
        <div className="mt-1 text-xs text-muted-foreground">{detail}</div>
      </div>
    </div>
  );
}

function SafetyRow({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-border bg-background px-3 py-3">
      <div className="flex items-center gap-2 text-sm">
        {good ? <CheckCircle2 className="text-success" size={16} /> : <AlertTriangle className="text-warning" size={16} />}
        <span>{label}</span>
      </div>
      <span className="text-sm font-medium">{value}</span>
    </div>
  );
}

function AssetCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="panel min-h-32">
      <div className="text-xs font-medium uppercase text-muted-foreground">{title}</div>
      <div className="mt-3 break-words text-sm leading-6">{value}</div>
    </div>
  );
}

function formatRecordCounts(counts?: Record<string, number>): string {
  if (!counts || Object.keys(counts).length === 0) {
    return 'No records';
  }

  return Object.entries(counts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([type, total]) => `${type} ${total}`)
    .join(', ');
}

function formatSecurityHeaders(summary: AssetSummary | null): string {
  const headers = summary?.security_headers ?? {};
  const entries = Object.values(headers);

  if (entries.length === 0) {
    return 'No header observation';
  }

  const present = entries.filter((header) => header.present).length;

  return `${present}/${entries.length} present`;
}

function StatusBadge({ status }: { status: string }) {
  const lowerStatus = status.toLowerCase();
  const className = ['verified', 'completed', 'ok'].includes(lowerStatus)
    ? 'status-badge status-good'
    : ['failed', 'timeout', 'cancelled', 'critical', 'high'].includes(lowerStatus)
      ? 'status-badge status-danger'
      : 'status-badge status-pending';

  return <span className={className}>{status}</span>;
}

function RiskBadge({ score, priority }: { score: number; priority: string }) {
  const className = ['critical', 'high'].includes(priority)
    ? 'status-badge status-danger'
    : priority === 'medium'
      ? 'status-badge status-pending'
      : 'status-badge status-good';

  return <span className={className}>{score} {priority}</span>;
}

function CodeLine({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-xs uppercase text-muted-foreground">{label}</div>
      <code className="block break-words rounded-md border border-border bg-background p-3 text-xs">{value}</code>
    </div>
  );
}

function readError(error: unknown): string {
  if (error instanceof ApiError) {
    const firstField = error.errors ? Object.values(error.errors)[0]?.[0] : null;
    return firstField ?? error.message;
  }

  return error instanceof Error ? error.message : 'Unexpected error';
}
