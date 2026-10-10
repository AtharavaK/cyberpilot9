// Shared type definitions for the CyberPilot frontend
// These match the backend Pydantic schemas in app/models/schemas.py

/**
 * @typedef {object} Scan
 * @property {string} scan_id
 * @property {string} target_url
 * @property {string} status
 * @property {number|null} overall_score
 * @property {string} created_at
 * @property {string} data_source
 * @property {string|null} executive_summary_pdf
 * @property {string|null} technical_report_pdf
 * @property {number} findings_count
 * @property {object|null} progress
 */

/**
 * @typedef {object} Finding
 * @property {number|null} id
 * @property {string} agent_name
 * @property {string|null} scanner
 * @property {string|null} tool
 * @property {string} severity
 * @property {number|null} confidence
 * @property {string|null} title
 * @property {string|null} category
 * @property {string} description
 * @property {string|null} evidence
 * @property {string|null} remediation
 * @property {string|null} target
 * @property {string|null} file
 * @property {number} line
 * @property {object|null} location
 * @property {Array<string>|null} cwe
 * @property {Array<string>|null} cve
 * @property {Array<string>|null} references
 * @property {string|null} status
 * @property {string|null} data_source
 * @property {string|null} created_at
 * @property {object|null} metadata
 * @property {object|null} remediation_details
 */

/**
 * @typedef {object} AIAnalysis
 * @property {number|null} finding_id
 * @property {string|null} scan_id
 * @property {string} summary
 * @property {string} risk_explanation
 * @property {string} exploitability
 * @property {string} impact
 * @property {string} false_positive_assessment
 * @property {number} confidence
 * @property {string|null} root_cause
 * @property {string} remediation
 * @property {Array<string>} references
 * @property {number|null} priority
 * @property {string} model
 * @property {string} created_at
 * @property {string} status
 * @property {string|null} error
 * @property {number|null} scanner_confidence
 * @property {string|null} scanner_severity
 */

/**
 * @typedef {object} Task
 * @property {string} task_id
 * @property {string} agent
 * @property {string} tool_name
 * @property {string} target
 * @property {string} scan_mode
 * @property {Array<string>} dependencies
 * @property {number} priority
 * @property {string} status
 * @property {string|null} error
 * @property {string|null} created_at
 * @property {string|null} started_at
 * @property {string|null} completed_at
 * @property {object} config
 * @property {object} agent_result_json
 */

/**
 * @typedef {object} Decision
 * @property {string} decision_id
 * @property {string} decision_type
 * @property {string} outcome
 * @property {string|null} reason
 * @property {string|null} task_id
 * @property {string|null} agent
 * @property {string|null} tool
 * @property {string|null} target
 * @property {string|null} policy_validation
 * @property {string} created_at
 */

/**
 * @typedef {object} ToolStatus
 * @property {string} name
 * @property {string} tool_name
 * @property {boolean} installed
 * @property {boolean} available
 * @property {string} status
 * @property {string|null} version
 * @property {boolean} enabled
 * @property {string|null} description
 */

/**
 * @typedef {object} ScanEvent
 * @property {number} id
 * @property {string} event_type
 * @property {object} payload
 * @property {string} created_at
 */

/**
 * @typedef {'pending'|'approved'|'running'|'completed'|'failed'|'cancelled'|'blocked'|'skipped'} TaskStatus
 */

/**
 * @typedef {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO'} Severity
 */

export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export const SEVERITY_CONFIG = {
  CRITICAL: { label: 'Critical', color: 'var(--error)', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)' },
  HIGH:     { label: 'High',     color: 'var(--error)', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)' },
  MEDIUM:   { label: 'Medium',   color: 'var(--warning)', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.3)' },
  LOW:      { label: 'Low',      color: 'var(--success)', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.3)' },
  INFO:     { label: 'Info',     color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.3)' },
};

export const TASK_STATUS_CONFIG = {
  pending:    { label: 'Pending',    color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.1)' },
  approved:   { label: 'Approved',   color: 'var(--accent-primary)', bg: 'rgba(0,240,255,0.1)' },
  running:    { label: 'Running',    color: 'var(--warning)', bg: 'rgba(245,158,11,0.1)' },
  completed:  { label: 'Completed',  color: 'var(--success)', bg: 'rgba(16,185,129,0.1)' },
  failed:     { label: 'Failed',     color: 'var(--error)', bg: 'rgba(239,68,68,0.1)' },
  cancelled:  { label: 'Cancelled',  color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.1)' },
  blocked:    { label: 'Blocked',    color: 'var(--error)', bg: 'rgba(239,68,68,0.1)' },
  skipped:    { label: 'Skipped',    color: 'var(--text-secondary)', bg: 'rgba(148,163,184,0.1)' },
};

export const SCAN_STATUS_LABELS = {
  INITIALIZING: 'Initializing',
  RECONNAISSANCE: 'Reconnaissance',
  SECURITY_ANALYSIS: 'Security Analysis',
  RISK_SCORING: 'Risk Scoring',
  COMPLIANCE_MAPPING: 'Compliance Mapping',
  RECOMMENDATIONS: 'Recommendations',
  COMPLETED: 'Complete',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
  PAUSED: 'Paused',
  TIMEOUT: 'Timeout',
};
