import React, { useEffect, useState, useRef } from 'react';
import {
  ShieldAlert, Activity, FileText, Bot, Clock, CheckCircle2, Loader2,
  Pause, Play, Square, Download, AlertTriangle, X, Calendar,
  BarChart3, Target, Users, Wrench,
} from 'lucide-react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  getScanStatus, getScanEvents, getScanTasks, getAgentResults,
  getScanDecisions, pauseScan, resumeScan, cancelScan,
  downloadExecutiveSummary, downloadTechnicalReport, getScanFindings,
} from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator, TaskStatusBadge, SeverityBadge } from '../components/ui.jsx';
import { SEVERITY_CONFIG, SCAN_STATUS_LABELS } from '../types/index.js';

const TAB_ORDER = ['overview', 'agents', 'tasks', 'findings', 'events', 'report'];
const TAB_LABELS = {
  overview: 'Overview',
  agents: 'Agents',
  tasks: 'Tasks',
  findings: 'Findings',
  events: 'Events',
  report: 'Report',
};

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [scanLoading, setScanLoading] = useState(true);
  const [scanError, setScanError] = useState(null);

  const [tasks, setTasks] = useState(null);
  const [decisions, setDecisions] = useState(null);
  const [agentResults, setAgentResults] = useState(null);
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState(null);
  const [loadingSections, setLoadingSections] = useState({ tasks: true, agents: true, decisions: true, events: true, findings: true });
  const [activeTab, setActiveTab] = useState('overview');
  const [polling, setPolling] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  const pollRef = useRef(null);
  const eventsSinceIdRef = useRef(0);

  const loadScan = async () => {
    setScanLoading(true);
    setScanError(null);
    try {
      const data = await getScanStatus(scanId);
      setScan(data);
    } catch (err) {
      setScanError(err.message || 'Failed to load scan');
    } finally {
      setScanLoading(false);
    }
  };

  const loadTasks = async () => {
    if (!scanId) return;
    setLoadingSections(s => ({ ...s, tasks: true }));
    try {
      const data = await getScanTasks(scanId);
      setTasks(data.tasks || []);
    } catch (err) {
      // 404 is OK — tasks may not exist yet
    } finally {
      setLoadingSections(s => ({ ...s, tasks: false }));
    }
  };

  const loadAgentResults = async () => {
    if (!scanId) return;
    setLoadingSections(s => ({ ...s, agents: true }));
    try {
      const data = await getAgentResults(scanId);
      setAgentResults(data.agent_results || []);
    } catch (err) {
      // ok
    } finally {
      setLoadingSections(s => ({ ...s, agents: false }));
    }
  };

  const loadDecisions = async () => {
    if (!scanId) return;
    setLoadingSections(s => ({ ...s, decisions: true }));
    try {
      const data = await getScanDecisions(scanId);
      setDecisions(data.decisions || []);
    } catch (err) {
      // ok
    } finally {
      setLoadingSections(s => ({ ...s, decisions: false }));
    }
  };

  const loadFindings = async () => {
    if (!scanId) return;
    setLoadingSections(s => ({ ...s, findings: true }));
    try {
      const data = await getScanFindings(scanId);
      setFindings(data);
    } catch (err) {
      // ok
    } finally {
      setLoadingSections(s => ({ ...s, findings: false }));
    }
  };

  const loadEvents = async () => {
    if (!scanId) return;
    try {
      const data = await getScanEvents(scanId, eventsSinceIdRef.current);
      if (data.events?.length > 0) {
        setEvents(prev => [...prev, ...data.events]);
        eventsSinceIdRef.current = data.events[data.events.length - 1]?.id || eventsSinceIdRef.current;
      }
    } catch (err) {
      // ok
    }
  };

  useEffect(() => {
    loadScan();
  }, [scanId]);

  useEffect(() => {
    if (scan?.status === 'COMPLETED' || scan?.status === 'FAILED' || scan?.status === 'CANCELLED' || scan?.status === 'TIMEOUT') {
      setPolling(false);
      if (pollRef.current) clearInterval(pollRef.current);
    }
  }, [scan]);

  // Polling for scan status
  useEffect(() => {
    if (!scanId || !polling) return;
    const interval = setInterval(() => {
      loadScan();
    }, 2000);
    pollRef.current = interval;
    return () => clearInterval(interval);
  }, [scanId, polling]);

  // Load sections when scan status changes
  useEffect(() => {
    if (scan && (scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'CANCELLED')) {
      loadTasks();
      loadAgentResults();
      loadDecisions();
      loadFindings();
      loadEvents();
    }
  }, [scan]);

  // Load events while running
  useEffect(() => {
    if (!scanId) return;
    const interval = setInterval(() => {
      loadEvents();
    }, 3000);
    return () => clearInterval(interval);
  }, [scanId]);

  // Tab-specific data loading
  const loadTabData = (tab) => {
    if (tab === 'tasks') loadTasks();
    if (tab === 'agents') loadAgentResults();
    if (tab === 'decisions') loadDecisions();
    if (tab === 'findings') loadFindings();
    if (tab === 'events') loadEvents();
  };

  useEffect(() => {
    if (scan) loadTabData(activeTab);
  }, [activeTab, scan]);

  const handlePause = async () => {
    setActionLoading('pause');
    try {
      await pauseScan(scanId);
      loadScan();
    } catch (err) {
      // error handled by scan reload
    } finally {
      setActionLoading(null);
    }
  };

  const handleResume = async () => {
    setActionLoading('resume');
    try {
      await resumeScan(scanId);
      loadScan();
    } catch (err) {
      // error handled by scan reload
    } finally {
      setActionLoading(null);
    }
  };

  const handleCancel = async () => {
    if (!confirm('Are you sure you want to cancel this assessment?')) return;
    setActionLoading('cancel');
    try {
      await cancelScan(scanId);
      loadScan();
    } catch (err) {
      // error handled by scan reload
    } finally {
      setActionLoading(null);
    }
  };

  const handleDownload = async (type) => {
    try {
      let blob;
      if (type === 'executive') {
        blob = await downloadExecutiveSummary(scanId);
      } else {
        blob = await downloadTechnicalReport(scanId);
      }
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${scanId}_${type === 'executive' ? 'executive_summary' : 'technical_report'}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download: ' + err.message);
    }
  };

  // Compute elapsed time
  const getElapsed = () => {
    if (!scan?.created_at) return '–';
    const start = new Date(scan.created_at).getTime();
    const now = Date.now();
    const elapsed = Math.floor((now - start) / 1000);
    const m = Math.floor(elapsed / 60);
    const s = elapsed % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  };

  // Tab content renderers
  const renderOverview = () => {
    if (!scan) return <LoadingSkeleton lines={10} />;
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Status Cards */}
        <div className="card-grid">
          <div className="stat-card">
            <div className="stat-label">Status</div>
            <div style={{ marginTop: '0.5rem' }}>
              <StatusIndicator status={
                scan.status === 'COMPLETED' ? 'completed' :
                scan.status === 'FAILED' ? 'error' :
                scan.status === 'CANCELLED' ? 'error' :
                scan.status === 'PAUSED' ? 'pending' : 'running'
              } />
              <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                {SCAN_STATUS_LABELS[scan.status] || scan.status}
              </div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Target</div>
            <div style={{ marginTop: '0.5rem', fontWeight: 600, wordBreak: 'break-all', fontSize: '0.9rem', color: 'var(--accent-primary)' }}>
              {scan.target_url || '—'}
            </div>
            <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
              {scan.data_source === 'simulation' ? 'Simulation Mode' : 'Live Assessment'}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Elapsed</div>
            <div className="stat-value" style={{ color: 'var(--accent-primary)' }}>{getElapsed()}</div>
          </div>
          {scan.overall_score !== null && scan.overall_score !== undefined && (
            <div className="stat-card">
              <div className="stat-label">Security Score</div>
              <div className="stat-value" style={{
                color: scan.overall_score >= 80 ? 'var(--success)' : scan.overall_score >= 60 ? 'var(--warning)' : 'var(--error)'
              }}>
                {scan.overall_score}/100
              </div>
              <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                {scan.overall_score >= 80 ? 'Good' : scan.overall_score >= 60 ? 'Fair' : 'Poor'} Posture
              </div>
            </div>
          )}
          <div className="stat-card">
            <div className="stat-label">Findings</div>
            <div className="stat-value" style={{ color: 'var(--error)' }}>{scan.findings_count ?? 0}</div>
          </div>
        </div>

        {/* Findings Distribution */}
        {scan.findings_count > 0 && findings && (
          <div className="glass-card" style={{ padding: '1.5rem' }}>
            <h3 style={{ margin: 0, marginBottom: '1rem', fontSize: '1.1rem' }}>Findings by Severity</h3>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => {
                const count = findings.findings?.filter(f => f.severity === sev).length || 0;
                if (count === 0) return null;
                return (
                  <div key={sev} style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '8px',
                    background: cfg.bg,
                    border: `1px solid ${cfg.border}`,
                    textAlign: 'center',
                  }}>
                    <div style={{ fontSize: '1.5rem', fontWeight: 700, color: cfg.color }}>{count}</div>
                    <div style={{ fontSize: '0.75rem', color: cfg.color, textTransform: 'uppercase' }}>{cfg.label}</div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Scan Controls */}
        {scan.status !== 'COMPLETED' && scan.status !== 'FAILED' && scan.status !== 'CANCELLED' && (
          <div className="glass-card" style={{ padding: '1rem 1.5rem', display: 'flex', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <strong>{SCAN_STATUS_LABELS[scan.status] || scan.status}</strong>
              <span className="text-muted" style={{ marginLeft: '0.75rem', fontSize: '0.85rem' }}>
                Elapsed: {getElapsed()}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {scan.status === 'PAUSED' && (
                <button className="btn btn-outline" onClick={handleResume} disabled={actionLoading === 'resume'}>
                  {actionLoading === 'resume' ? <Loader2 size={14} style={{ animation: 'spin 0.6s linear infinite' }} /> : <Play size={14} />}
                  Resume
                </button>
              )}
              {scan.status !== 'PAUSED' && scan.status !== 'CANCELLED' && (
                <button className="btn btn-outline" onClick={handlePause} disabled={actionLoading === 'pause'}>
                  {actionLoading === 'pause' ? <Loader2 size={14} style={{ animation: 'spin 0.6s linear infinite' }} /> : <Pause size={14} />}
                  Pause
                </button>
              )}
              <button className="btn btn-outline" onClick={handleCancel} disabled={actionLoading === 'cancel'}
                style={{ borderColor: 'rgba(239,68,68,0.3)', color: 'var(--error)' }}>
                {actionLoading === 'cancel' ? <Loader2 size={14} style={{ animation: 'spin 0.6s linear infinite' }} /> : <Square size={14} />}
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Report Downloads */}
        {scan.status === 'COMPLETED' && (
          <div className="glass-card" style={{ padding: '1.5rem' }}>
            <h3 style={{ margin: 0, marginBottom: '1rem', fontSize: '1.1rem' }}>Reports</h3>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <button className="btn btn-outline" onClick={() => handleDownload('executive')}>
                <Download size={16} /> Executive Summary (PDF)
              </button>
              <button className="btn btn-outline" onClick={() => handleDownload('technical')}>
                <Download size={16} /> Technical Report (PDF)
              </button>
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderTasks = () => {
    if (loadingSections.tasks) return <LoadingSkeleton lines={8} />;
    if (!tasks || tasks.length === 0) {
      return (
        <div className="empty-state">
          <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No tasks created yet</div>
          <div className="empty-desc">Tasks are created during the planning phase. Check back after the scan starts.</div>
        </div>
      );
    }
    return (
      <div className="finding-list">
        {tasks.map((task) => (
          <div key={task.task_id} className="finding-item" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{task.agent}</h4>
              <TaskStatusBadge status={task.status} />
            </div>
            <div className="text-muted" style={{ fontSize: '0.85rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <span>Tool: {task.tool_name}</span>
              <span>Mode: {task.scan_mode}</span>
              <span>Priority: {task.priority}</span>
              {task.target && <span>Target: {task.target}</span>}
            </div>
            {task.error && (
              <div style={{ marginTop: '0.5rem', color: 'var(--error)', fontSize: '0.85rem' }}>
                <AlertTriangle size={14} style={{ marginRight: '0.3rem' }} />
                {task.error}
              </div>
            )}
            {task.started_at && task.completed_at && (
              <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.3rem' }}>
                Started: {new Date(task.started_at).toLocaleTimeString()} — Completed: {new Date(task.completed_at).toLocaleTimeString()}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderAgents = () => {
    if (loadingSections.agents) return <LoadingSkeleton lines={10} />;
    if (!agentResults || agentResults.length === 0) {
      return (
        <div className="empty-state">
          <Bot size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No agent activity yet</div>
          <div className="empty-desc">Agents are dispatched during the assessment. Check back after tasks are created.</div>
        </div>
      );
    }
    return (
      <div className="finding-list">
        {agentResults.map((agent, i) => (
          <div key={i} className="finding-item" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{agent.agent}</h4>
              <TaskStatusBadge status={agent.status} />
            </div>
            <div className="text-muted" style={{ fontSize: '0.85rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
              <span>Tool: {agent.tool}</span>
              <span>Objective: {agent.objective}</span>
              {agent.scan_mode && <span>Mode: {agent.scan_mode}</span>}
            </div>
            {agent.agent_result_json && Object.keys(agent.agent_result_json) && (
              <div style={{ marginTop: '0.5rem' }}>
                <div className="text-muted" style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                  Findings: {agent.agent_result_json.findings_count || agent.agent_result_json.findings?.length || 0}
                </div>
                {agent.agent_result_json.errors?.length > 0 && (
                  <div style={{ color: 'var(--error)', fontSize: '0.8rem' }}>
                    Errors: {agent.agent_result_json.errors.join(', ')}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };

  const renderFindings = () => {
    if (loadingSections.findings) return <LoadingSkeleton lines={8} />;
    if (!findings || !findings.total_findings || findings.total_findings === 0) {
      return (
        <div className="empty-state">
          <ShieldAlert size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No findings reported</div>
          <div className="empty-desc">No vulnerabilities were detected by any scanner. This does not guarantee the target is secure.</div>
        </div>
      );
    }
    return (
      <div className="finding-list">
        {findings.by_severity?.map((group) => (
          group.findings?.map((f) => (
            <div key={f.id || `${f.agent_name}-${f.title}`} className="finding-item" style={{ padding: '1rem', borderLeft: `4px solid ${SEVERITY_CONFIG[f.severity]?.color || 'var(--text-secondary)'}`, backgroundColor: SEVERITY_CONFIG[f.severity]?.bg || 'transparent' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{f.title || f.description?.slice(0, 80)}</h4>
                <SeverityBadge severity={f.severity} />
              </div>
              <div className="text-muted" style={{ fontSize: '0.85rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                <span>Scanner: {f.scanner || f.agent_name}</span>
                {f.confidence != null && <span>Confidence: {Math.round(f.confidence * 100)}%</span>}
                {f.cwe && f.cwe.length > 0 && <span>CWE: {f.cwe.join(', ')}</span>}
              </div>
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginTop: '0.5rem' }}>
                {f.description}
              </p>
              <div style={{ marginTop: '0.5rem' }}>
                <button
                  className="btn btn-outline"
                  style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}
                  onClick={() => navigate(`/scans/${scanId}/findings/${f.id || 0}`)}
                >
                  View Details
                </button>
              </div>
            </div>
          ))
        ))}
      </div>
    );
  };

  const renderDecisions = () => {
    if (loadingSections.decisions) return <LoadingSkeleton lines={6} />;
    if (!decisions || decisions.length === 0) {
      return (
        <div className="empty-state">
          <Activity size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No policy decisions recorded</div>
          <div className="empty-desc">Policy decisions are recorded when the Master Agent evaluates tasks and findings.</div>
        </div>
      );
    }
    return (
      <div className="finding-list">
        {decisions.map((dec) => (
          <div key={dec.decision_id} className="finding-item" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{dec.decision_type || 'Decision'}</h4>
              <span className={`badge ${dec.outcome === 'approved' || dec.outcome === 'APPROVED' ? 'success' : dec.outcome === 'blocked' || dec.outcome === 'BLOCKED' ? 'error' : 'warning'}`} style={{ fontSize: '0.7rem' }}>
                {dec.outcome || 'pending'}
              </span>
            </div>
            {dec.reason && (
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginTop: '0.25rem' }}>
                {dec.reason}
              </p>
            )}
            {dec.agent && (
              <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>
                Agent: {dec.agent}{dec.tool ? ` · Tool: ${dec.tool}` : ''}{dec.target ? ` · Target: ${dec.target}` : ''}
              </div>
            )}
            <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>
              {new Date(dec.created_at).toLocaleString()} · Decision ID: {dec.decision_id?.slice(0, 8)}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderEvents = () => {
    return (
      <div className="event-log">
        {events.length === 0 ? (
          <div className="empty-state" style={{ padding: '2rem' }}>
            <Clock size={32} style={{ opacity: 0.2, margin: '0 auto 0.5rem' }} />
            <div className="empty-title">No events yet</div>
            <div className="empty-desc">Events will appear here as the assessment progresses.</div>
          </div>
        ) : (
          events.map((ev) => {
            const payload = ev.payload || {};
            const desc = payload.message || payload.action || payload.event_type || ev.event_type || 'Event';
            return (
              <div key={ev.id} className="event-item">
                <span className="event-time">
                  {new Date(ev.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
                <span className="event-type">{ev.event_type}</span>
                <span>{desc}</span>
                {payload.findings_count !== undefined && (
                  <span className="text-muted" style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
                    {payload.findings_count} findings
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>
    );
  };

  const renderReport = () => {
    if (scan?.status !== 'COMPLETED') {
      return (
        <div className="empty-state">
          <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">Report not available yet</div>
          <div className="empty-desc">Reports are generated when the assessment completes.</div>
        </div>
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <h3 style={{ margin: 0, marginBottom: '1rem', fontSize: '1.1rem' }}>Download Reports</h3>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            <button className="btn btn-outline" onClick={() => handleDownload('executive')}>
              <Download size={16} /> Executive Summary (PDF)
            </button>
            <button className="btn btn-outline" onClick={() => handleDownload('technical')}>
              <Download size={16} /> Technical Report (PDF)
            </button>
          </div>
        </div>
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <h3 style={{ margin: 0, marginBottom: '1rem', fontSize: '1.1rem' }}>Assessment Summary</h3>
          <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
            <div>
              <span className="text-muted">Target:</span>
              <span style={{ marginLeft: '0.5rem', fontWeight: 500 }}>{scan.target_url}</span>
            </div>
            <div>
              <span className="text-muted">Score:</span>
              <span style={{ marginLeft: '0.5rem', fontWeight: 500 }}>{scan.overall_score ?? 'N/A'}/100</span>
            </div>
            <div>
              <span className="text-muted">Findings:</span>
              <span style={{ marginLeft: '0.5rem', fontWeight: 500 }}>{scan.findings_count ?? 0}</span>
            </div>
            <div>
              <span className="text-muted">Data Source:</span>
              <span style={{ marginLeft: '0.5rem', fontWeight: 500 }}>{scan.data_source}</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  if (scanLoading) {
    return (
      <div>
        <header style={{ marginBottom: '2rem' }}>
          <h1 className="heading-1">Loading Assessment…</h1>
        </header>
        <LoadingSkeleton lines={20} />
      </div>
    );
  }

  if (scanError) {
    return (
      <div>
        <ErrorBanner error={scanError} onRetry={loadScan} />
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <ShieldAlert size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Assessment {scan?.scan_id?.slice(0, 8)}…</h1>
        </div>
        <div className="text-muted">
          {scan?.target_url} · {scan?.status ? SCAN_STATUS_LABELS[scan.status] || scan.status : ''}
        </div>
      </header>

      {/* Tabs */}
      <div className="tabs">
        {TAB_ORDER.map((tab) => (
          <button
            key={tab}
            type="button"
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {TAB_LABELS[tab]}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && renderOverview()}
      {activeTab === 'agents' && renderAgents()}
      {activeTab === 'tasks' && renderTasks()}
      {activeTab === 'findings' && renderFindings()}
      {activeTab === 'events' && renderEvents()}
      {activeTab === 'report' && renderReport()}
    </div>
  );
}
