import React, { useEffect, useState, useMemo } from 'react';
import { Search, Filter, AlertTriangle, Globe, BarChart3, Loader2, ChevronLeft } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { listAllScans, getScanFindings, getScanTriage, setFindingTriage } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, SeverityBadge, TaskStatusBadge } from '../components/ui.jsx';
import { SEVERITY_CONFIG } from '../types/index.js';

const SEVERITY_FILTERS = ['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const TRIAGE_FILTERS = ['all', 'open', 'confirmed', 'false_positive', 'accepted', 'remediated'];
const SORT_OPTIONS = [
  { value: 'severity', label: 'Severity' },
  { value: 'confidence', label: 'Confidence' },
  { value: 'created_at', label: 'Newest' },
];

export default function FindingsPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [findingsCache, setFindingsCache] = useState({});
  const [filters, setFilters] = useState({
    scanId: 'all',
    severity: 'all',
    triage: 'all',
    search: '',
    sort: 'severity',
  });

  useEffect(() => {
    const loadScans = async () => {
      setLoading(true);
      try {
        const data = await listAllScans();
        setScans(data);
      } catch (err) {
        setError(err.message || 'Failed to load scans');
      } finally {
        setLoading(false);
      }
    };
    loadScans();
  }, []);

  // Load findings from all completed scans
  const completedScans = useMemo(() => scans.filter(s => s.status === 'COMPLETED'), [scans]);
  const [allFindings, setAllFindings] = useState([]);

  useEffect(() => {
    const loadFindings = async () => {
      if (completedScans.length === 0) {
        setAllFindings([]);
        setLoadingFindings(false);
        return;
      }
      setLoadingFindings(true);
      try {
        const cache = {};
        const findings = [];
        for (const scan of completedScans) {
          try {
            const data = await getScanFindings(scan.scan_id);
            if (data.total_findings > 0) {
              cache[scan.scan_id] = data;
              data.by_severity?.forEach(group => {
                group.findings?.forEach(f => {
                  findings.push({ ...f, scan_id: scan.scan_id, target_url: scan.target_url });
                });
              });
            }
          } catch (err) {
            // skip scans with no findings API
          }
        }
        setFindingsCache(cache);
        setAllFindings(findings);
      } catch (err) {
        setError(err.message || 'Failed to load findings');
      } finally {
        setLoadingFindings(false);
      }
    };
    loadFindings();
  }, [completedScans]);

  // Apply filters and sorting
  const filteredFindings = allFindings
    .filter(f => {
      if (filters.severity !== 'all' && f.severity !== filters.severity) return false;
      if (filters.scanId !== 'all' && f.scan_id !== filters.scanId) return false;
      if (filters.search && !f.title?.toLowerCase().includes(filters.search.toLowerCase()) &&
          !f.description?.toLowerCase().includes(filters.search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      if (filters.sort === 'severity') {
        const sa = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[a.severity] || 99;
        const sb = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[b.severity] || 99;
        return sa - sb;
      }
      if (filters.sort === 'confidence') {
        return (b.confidence || 0) - (a.confidence || 0);
      }
      if (filters.sort === 'created_at') {
        return new Date(b.created_at || '') - new Date(a.created_at || '');
      }
      return 0;
    });

  const severityCounts = {};
  allFindings.forEach(f => {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  });

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  if (loading) return <LoadingSkeleton lines={10} />;

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Search size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Findings</h1>
        </div>
        <p className="text-muted">Browse and triage all findings across completed assessments.</p>
      </header>

      {error && <ErrorBanner error={error} />}

      {/* Filters */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={16} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.85rem' }}>Filters:</span>
          </div>

          <select
            className="form-input"
            style={{ maxWidth: '180px', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}
            value={filters.scanId}
            onChange={(e) => handleFilterChange('scanId', e.target.value)}
          >
            <option value="all">All Scans</option>
            {completedScans.map(s => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.target_url} ({s.scan_id.slice(0, 8)})
              </option>
            ))}
          </select>

          <select
            className="form-input"
            style={{ maxWidth: '150px', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            {SEVERITY_FILTERS.map(s => (
              <option key={s} value={s}>
                {s === 'all' ? 'All Severity' : s}
              </option>
            ))}
          </select>

          <select
            className="form-input"
            style={{ maxWidth: '150px', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}
            value={filters.sort}
            onChange={(e) => handleFilterChange('sort', e.target.value)}
          >
            {SORT_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>

          <input
            type="text"
            className="form-input"
            style={{ maxWidth: '200px', padding: '0.4rem 0.75rem', fontSize: '0.85rem' }}
            placeholder="Search findings..."
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
          />
        </div>
      </div>

      {/* Results */}
      {loadingFindings ? (
        <LoadingSkeleton lines={8} />
      ) : filteredFindings.length === 0 ? (
        <div className="empty-state">
          <Search size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No findings match your filters</div>
          <div className="empty-desc">Try adjusting your search or filter criteria.</div>
        </div>
      ) : (
        <div className="finding-list">
          {filteredFindings.map((f) => (
            <div key={`${f.scan_id}-${f.id || `${f.agent_name}-${f.title}`}`} className="finding-item" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <SeverityBadge severity={f.severity} size="md" />
                  <h4 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{f.title || f.description?.slice(0, 60)}</h4>
                </div>
                <button
                  className="btn btn-outline"
                  style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}
                  onClick={() => navigate(`/scans/${f.scan_id}/findings/${f.id || 0}`)}
                >
                  View
                </button>
              </div>
              <div className="text-muted" style={{ fontSize: '0.85rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.3rem' }}>
                <span>Scanner: {f.scanner || f.agent_name}</span>
                <span>Target: {f.target || f.target_url}</span>
                {f.cwe && f.cwe.length > 0 && <span>CWE: {f.cwe.join(', ')}</span>}
                {f.confidence != null && <span>Confidence: {Math.round(f.confidence * 100)}%</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Summary */}
      {allFindings.length > 0 && (
        <div className="glass-card" style={{ padding: '1.5rem', marginTop: '1.5rem' }}>
          <h3 style={{ margin: 0, marginBottom: '1rem', fontSize: '1.1rem' }}>Severity Distribution</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => {
              const count = severityCounts[sev] || 0;
              return count > 0 ? (
                <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ minWidth: '70px', fontSize: '0.85rem' }}>{cfg.label}</span>
                  <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: `${Math.min(100, count * 5)}%`, height: '100%', background: cfg.color, borderRadius: '4px' }} />
                  </div>
                  <span style={{ minWidth: '30px', textAlign: 'right', fontWeight: 600 }}>{count}</span>
                </div>
              ) : null;
            })}
          </div>
        </div>
      )}
    </div>
  );
}
