"""
Phase 5: Structured planning, task model, and agent abstractions
for the Master Security Agent.

This module defines the data structures and the MasterSecurityAgent class that
orchestrates the autonomous multi-agent security assessment workflow.

Key design principles:
  - AI assists planning, but all executable tasks are structured (no raw commands).
  - A SecurityPolicy layer validates every task before execution.
  - The Master Agent never directly executes shell commands — all tool execution
    goes through ToolManager/scanner abstractions.
  - All decisions are recorded for auditability.
"""
import uuid
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from app.services.finding_normalizer import normalize_severity
from app.services.ai_engine import AIEngine, AIUnavailableError

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class DecisionType(str, Enum):
    PLAN = "plan"
    TASK_CREATE = "task_create"
    TASK_APPROVE = "task_approve"
    TASK_BLOCK = "task_block"
    TOOL_SELECT = "tool_select"
    FOLLOW_UP = "follow_up"
    STOP = "stop"
    SCOPE_CHANGE = "scope_change"


class DecisionOutcome(str, Enum):
    APPROVED = "approved"
    BLOCKED = "blocked"
    REQUIRES_APPROVAL = "requires_approval"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Priority is inverted: lower number = higher priority
class Priority(int):
    """Priority for security tasks: 1 (highest) to 5 (lowest)."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

    @classmethod
    def from_severity(cls, severity: str) -> int:
        sev = severity.upper() if isinstance(severity, str) else "INFO"
        return {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
            "INFO": cls.INFO,
        }.get(sev, cls.INFO)


# ── Core Data Models ───────────────────────────────────────────────────────────

@dataclass
class SecurityTask:
    """A single structured security task in the assessment plan.

    Tasks are created by the Master Agent (AI-assisted) and validated by the
    SecurityPolicy before execution. They are NEVER arbitrary shell commands.
    """
    task_id: str
    agent: str                          # e.g. "Reconnaissance Agent"
    tool: str                           # e.g. "nmap", "zap", "semgrep"
    objective: str                      # human-readable description
    target: str                         # the target URL or path
    priority: int = Priority.MEDIUM     # 1 (highest) to 5 (lowest)
    status: str = TaskStatus.PENDING.value
    dependencies: List[str] = field(default_factory=list)  # task_ids this depends on
    reason: str = ""                    # why this task was created
    config: Dict[str, Any] = field(default_factory=dict)    # tool-specific config
    scan_mode: str = "passive"          # for web tools (passive/baseline/active)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    agent_result: Optional[Dict[str, Any]] = None  # populated after execution

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "tool": self.tool,
            "objective": self.objective,
            "target": self.target,
            "priority": self.priority,
            "status": self.status,
            "dependencies": self.dependencies,
            "reason": self.reason,
            "config": self.config,
            "scan_mode": self.scan_mode,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class AssessmentPlan:
    """Structured assessment plan created by the Master Agent.

    The plan is AI-assisted (AIEngine may suggest tasks) but always passes
    through SecurityPolicy validation before any task executes.
    """
    target: str
    target_kind: str                    # "url" | "git_repo" | "local_path" | "invalid"
    authorized_target: str
    authorization_mode: str             # "explicit" | "simulate"
    allow_active_scanning: bool
    allow_private_targets: bool
    objective: str
    tasks: List[SecurityTask] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Resource budgets
    max_iterations: int = 5
    max_tasks: int = 30
    max_runtime_seconds: int = 900  # 15 minutes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "target_kind": self.target_kind,
            "authorized_target": self.authorized_target,
            "authorization_mode": self.authorization_mode,
            "allow_active_scanning": self.allow_active_scanning,
            "allow_private_targets": self.allow_private_targets,
            "objective": self.objective,
            "tasks": [t.to_dict() for t in self.tasks],
            "constraints": self.constraints,
            "max_iterations": self.max_iterations,
            "max_tasks": self.max_tasks,
            "max_runtime_seconds": self.max_runtime_seconds,
            "created_at": self.created_at,
        }


@dataclass
class AgentResult:
    """Structured result from running a security agent/tool.

    Replaces free-form agent-to-agent communication with structured data.
    """
    agent: str
    task_id: str
    status: str                         # ScanStatus value (completed, failed, etc.)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "task_id": self.task_id,
            "status": self.status,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "observations": self.observations,
            "recommendations": self.recommendations,
            "tool_results": self.tool_results,
            "errors": self.errors,
            "duration": self.duration,
        }


@dataclass
class MasterDecision:
    """A single decision made by the Master Security Agent.

    All decisions are recorded for auditability (Phase 5 §22).
    """
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    decision_type: str = ""             # DecisionType value
    outcome: str = ""                   # DecisionOutcome value (approved/blocked/requires_approval)
    reason: str = ""
    task_id: Optional[str] = None
    agent: Optional[str] = None
    tool: Optional[str] = None
    target: Optional[str] = None
    policy_validation: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type,
            "outcome": self.outcome,
            "reason": self.reason,
            "task_id": self.task_id,
            "agent": self.agent,
            "tool": self.tool,
            "target": self.target,
            "policy_validation": self.policy_validation,
            "created_at": self.created_at,
        }


# ── Security Policy ────────────────────────────────────────────────────────────

@dataclass
class PolicyValidation:
    """Result of validating a task against the security policy."""
    approved: bool
    reason: str
    decision: str  # "approved" | "blocked" | "requires_approval"
    blocked_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approved": self.approved,
            "reason": self.reason,
            "decision": self.decision,
            "blocked_reasons": self.blocked_reasons,
        }


class SecurityPolicy:
    """Policy validation layer between AI planning and tool execution.

    Nothing executes without passing through this layer. (Phase 5 §8)

    Validates:
      - target scope (must match authorized_target)
      - target type (scheme, path validation)
      - allowed tools (against a whitelist)
      - scan mode (active scanning requires explicit authorization)
      - private target policy (SSRF protection)
      - resource limits (max tasks, max runtime)
      - cancellation state
    """

    ALLOWED_TOOLS = {
        "nmap", "semgrep", "bandit", "gitleaks", "trivy", "zap", "ai_tester",
    }

    def __init__(
        self,
        authorized_target: str,
        authorization_mode: str = "explicit",
        allow_active_scanning: bool = False,
        allow_private_targets: bool = False,
        max_tasks: int = 30,
        max_runtime_seconds: int = 900,
        allowed_tools: Optional[set] = None,
    ):
        self.authorized_target = authorized_target
        self.authorization_mode = authorization_mode
        self.allow_active_scanning = allow_active_scanning
        self.allow_private_targets = allow_private_targets
        self.max_tasks = max_tasks
        self.max_runtime_seconds = max_runtime_seconds
        self.allowed_tools = allowed_tools or self.ALLOWED_TOOLS

    def validate_task(self, task: SecurityTask, scan_cancelled: bool = False) -> PolicyValidation:
        """Validate a single task against the security policy."""
        blocked_reasons: List[str] = []

        # 1. Cancellation state
        if scan_cancelled:
            blocked_reasons.append("Scan has been cancelled")

        # 2. Allowed tool
        if task.tool not in self.allowed_tools:
            blocked_reasons.append(
                f"Tool '{task.tool}' is not in the allowed tools list: "
                f"{sorted(self.allowed_tools)}"
            )

        # 3. Target scope — must match authorized target
        if not self._is_within_scope(task.target, self.authorized_target):
            blocked_reasons.append(
                f"Task target '{task.target}' exceeds authorized scope "
                f"'{self.authorized_target}'"
            )

        # 4. Active scanning requires explicit authorization
        if task.scan_mode == "active" and not self.allow_active_scanning:
            blocked_reasons.append(
                "Active scanning requires explicit authorization "
                "(allow_active_scanning=True)"
            )

        # 5. Private target policy (SSRF protection)
        from app.services.target_validation import validate_target
        is_valid, reason = validate_target(
            task.target, allow_private=self.allow_private_targets
        )
        if not is_valid:
            blocked_reasons.append(f"Target validation failed: {reason}")

        # 6. Authorization mode check
        if self.authorization_mode == "simulate" and task.scan_mode == "active":
            blocked_reasons.append("Active scanning not allowed in simulation mode")

        if blocked_reasons:
            joined = "; ".join(blocked_reasons)
            return PolicyValidation(
                approved=False,
                reason=joined,
                decision=DecisionOutcome.BLOCKED.value,
                blocked_reasons=blocked_reasons,
            )

        return PolicyValidation(
            approved=True,
            reason="All policy checks passed",
            decision=DecisionOutcome.APPROVED.value,
        )

    def validate_plan(self, plan: AssessmentPlan, scan_cancelled: bool = False) -> PolicyValidation:
        """Validate an entire assessment plan."""
        blocked_reasons: List[str] = []

        if len(plan.tasks) > self.max_tasks:
            blocked_reasons.append(
                f"Plan exceeds max_tasks limit ({len(plan.tasks)} > {self.max_tasks})"
            )

        for task in plan.tasks:
            result = self.validate_task(task, scan_cancelled=scan_cancelled)
            if not result.approved:
                blocked_reasons.append(f"Task '{task.task_id}' ({task.tool}): {result.reason}")

        if blocked_reasons:
            return PolicyValidation(
                approved=False,
                reason="; ".join(blocked_reasons),
                decision=DecisionOutcome.BLOCKED.value,
                blocked_reasons=blocked_reasons,
            )

        return PolicyValidation(
            approved=True,
            reason="Plan passed all policy checks",
            decision=DecisionOutcome.APPROVED.value,
        )

    @staticmethod
    def _is_within_scope(target: str, authorized_target: str) -> bool:
        """Check if *target* is within the *authorized_target* scope.

        For web URLs, compares hostnames — subdomains of the authorized
        target are in scope, as are paths under the authorized target.
        For filesystem paths, checks path containment.

        Future: support CIDR, wildcard patterns, and regex.
        """
        from urllib.parse import urlparse

        # Try URL-based comparison first
        target_parsed = urlparse(target)
        authorized_parsed = urlparse(authorized_target)

        if target_parsed.scheme in ("http", "https") and authorized_parsed.scheme in ("http", "https"):
            target_host = (target_parsed.hostname or "").lower()
            auth_host = (authorized_parsed.hostname or "").lower()

            if not target_host or not auth_host:
                return False

            # Exact host match — always in scope
            if target_host == auth_host:
                return True

            # Subdomain of authorized host (api.example.com → example.com)
            if target_host.endswith("." + auth_host) or target_host == auth_host:
                return True

            # Authorized host is a subdomain of target (narrower scope)
            if auth_host.endswith("." + target_host):
                return True

            return False

        # Filesystem path comparison
        if target == authorized_target:
            return True
        if authorized_target and target.startswith(authorized_target.rstrip("/") + "/"):
            return True

        return False


# ── Master Security Agent ──────────────────────────────────────────────────────

class MasterSecurityAgent:
    """The Master Security Agent — autonomous orchestrator.

    Responsibilities (Phase 5 §4):
      1. Understand target
      2. Inspect normalized target
      3. Determine applicable agents
      4. Create assessment plan
      5. Delegate tasks (through ToolManager, never directly)
      6. Collect results
      7. Analyze findings (via AIEngine)
      8. Determine whether additional testing is justified
      9. Prioritize remaining tasks
      10. Stop when completion criteria are reached
      11. Produce final assessment

    The Master Agent NEVER directly executes shell commands.
    All execution goes through ToolManager. (Phase 5 §2)
    """

    def __init__(self, ai_engine: Optional[AIEngine] = None):
        self.ai_engine = ai_engine or AIEngine()
        self.tool_manager = None  # lazily created to avoid circular import

    def _get_tool_manager(self):
        if self.tool_manager is None:
            from app.services.tool_manager import ToolManager
            self.tool_manager = ToolManager()
        return self.tool_manager

    # ── Planning ──────────────────────────────────────────────────────────────

    def create_assessment_plan(
        self,
        target: str,
        target_kind: str,
        target_normalized: Dict[str, Any],
        authorize: bool = False,
    ) -> AssessmentPlan:
        """Create a structured AssessmentPlan based on the normalized target.

        Uses target kind to determine which agents/tools to enable.
        Does NOT use AI for initial plan creation — deterministic routing
        based on target normalization (Phase 1 logic). AI is used for
        follow-up task creation from findings.
        """
        web_target = target_normalized.get("web_target")
        local_path = target_normalized.get("local_path")

        allow_private = authorize
        allow_active = authorize  # active scanning requires explicit authorization

        authorization_mode = "explicit" if authorize else "simulate"

        plan = AssessmentPlan(
            target=target,
            target_kind=target_kind,
            authorized_target=target if web_target else (local_path or target),
            authorization_mode=authorization_mode,
            allow_active_scanning=allow_active,
            allow_private_targets=allow_private,
            objective=f"Security assessment of {target_kind}: {target}",
            constraints={
                "max_iterations": 5,
                "max_tasks": 30,
                "max_runtime_seconds": 900,
                "max_concurrent_tasks": 1,
            },
        )

        # Target-aware task selection (Phase 5 §6)
        # local_path → code scanners + infra + recon (if not git repo)
        # url → web + API + AI + recon
        # git_repo → clone + code scanners + infra

        tasks: List[SecurityTask] = []

        # Reconnaissance (always first if network target)
        if target_kind in ("url", "git_repo"):
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Reconnaissance Agent",
                tool="nmap",
                objective="Port and service discovery",
                target=web_target or target,
                priority=Priority.CRITICAL,
                reason="Identify attack surface before targeted scanning.",
                scan_mode="passive",
            ))

        # HTTP recon is part of the recon phase in the existing workflow
        # but we track it as an observation here

        # Code Security Agent (local_path or git_repo)
        if local_path and target_kind in ("local_path", "git_repo"):
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Code Review Agent",
                tool="semgrep",
                objective="Static analysis for code-level vulnerabilities",
                target=local_path,
                priority=Priority.HIGH,
                reason="Target is a local source repository.",
            ))
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Code Review Agent",
                tool="bandit",
                objective="Python-specific security linting",
                target=local_path,
                priority=Priority.HIGH,
                reason="Target contains Python source code.",
            ))
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Code Review Agent",
                tool="gitleaks",
                objective="Secret detection in repository",
                target=local_path,
                priority=Priority.HIGH,
                reason="Repository may contain committed secrets.",
            ))

        # Web/API Security Agent (web target only)
        if web_target and target_kind == "url":
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Web Security Agent",
                tool="zap",
                objective="Passive web application scanning",
                target=web_target,
                priority=Priority.HIGH,
                reason="Target is a live web application.",
                scan_mode="passive",
            ))

            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="API Security Agent",
                tool="zap",
                objective="API endpoint security analysis",
                target=web_target,
                priority=Priority.HIGH,
                reason="Target is a web application with API surface.",
                scan_mode="passive",
            ))

            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="AI Security Agent",
                tool="ai_tester",
                objective="AI/LLM security testing",
                target=web_target,
                priority=Priority.MEDIUM,
                reason="Target may expose LLM endpoints.",
            ))

        # Infrastructure Agent (always — Trivy handles both local and web)
        infra_target = local_path if local_path else web_target
        if infra_target:
            tasks.append(SecurityTask(
                task_id=str(uuid.uuid4()),
                agent="Infrastructure Agent",
                tool="trivy",
                objective="Infrastructure vulnerability and misconfiguration scan",
                target=infra_target,
                priority=Priority.MEDIUM,
                reason="Infrastructure assessment complements code and web scans.",
            ))

        plan.tasks = tasks
        return plan

    # ── Follow-up task creation from findings ────────────────────────────────

    def evaluate_finding_for_followup(
        self,
        finding: Dict[str, Any],
        ai_analysis: Optional[Dict[str, Any]] = None,
        authorized_target: str = "",
        allow_active: bool = False,
    ) -> Optional[SecurityTask]:
        """Evaluate a finding and determine if a follow-up task is warranted.

        Returns a SecurityTask if follow-up is needed, None otherwise.
        Uses AIEngine analysis if available to assess exploitability.
        """
        severity = finding.get("severity", "INFO")
        confidence = finding.get("confidence")
        category = finding.get("category", "")
        metadata = finding.get("metadata", {}) or {}
        tool = metadata.get("tool", "unknown")

        # Determine if follow-up is useful
        # High severity + moderate confidence → follow-up
        # Low severity + low confidence → skip
        is_high_value = severity in ("CRITICAL", "HIGH") and (
            confidence is None or (confidence is not None and confidence >= 0.5)
        )

        # Use AI analysis for exploitability assessment if available
        ai_confidence = None
        ai_exploitability = None
        if ai_analysis:
            ai_confidence = ai_analysis.get("confidence")
            ai_exploitability = ai_analysis.get("exploitability")

        # If AI says exploitability is "low" and severity is not critical,
        # skip detailed follow-up
        if ai_exploitability == "low" and severity != "CRITICAL":
            is_high_value = False

        if not is_high_value:
            return None

        # Determine follow-up tool based on finding context
        followup_tool = None
        followup_agent = None
        followup_reason = ""

        if "sql" in category.lower() or "injection" in category.lower():
            followup_tool = "zap"
            followup_agent = "API Security Agent"
            followup_reason = (
                f"Potential {category} finding suggests endpoint may be exploitable. "
                f"Targeted ZAP active scan could validate."
            )
        elif "xss" in category.lower() or "cross" in category.lower():
            followup_tool = "zap"
            followup_agent = "Web Security Agent"
            followup_reason = (
                f"Reflected XSS finding in {category}. "
                f"ZAP active scan could confirm exploitability."
            )
        elif "secret" in category.lower() or "credential" in category.lower():
            # Don't auto-exploit — just flag for manual review
            return None  # secrets are findings themselves, no follow-up scan needed
        elif "open port" in category.lower() or "port" in metadata:
            followup_tool = "nmap"
            followup_agent = "Reconnaissance Agent"
            followup_reason = (
                "Open port discovered — version detection could reveal vulnerable services."
            )

        if not followup_tool:
            return None

        assert followup_agent is not None, "followup_agent must be set when followup_tool is set"
        scan_mode = "active" if (
            allow_active and followup_tool in ("zap", "nmap")
        ) else "passive"

        if scan_mode == "active" and not allow_active:
            scan_mode = "passive"

        task = SecurityTask(
            task_id=str(uuid.uuid4()),
            agent=followup_agent,
            tool=followup_tool,
            objective=f"Validate {category} finding via {followup_tool} {scan_mode} scan",
            target=finding.get("target", finding.get("location", {}).get("url", "")) or authorized_target,
            priority=Priority.from_severity(severity),
            reason=followup_reason,
            scan_mode=scan_mode,
            dependencies=[],
        )

        return task

    # ── Stopping criteria ────────────────────────────────────────────────────

    def should_stop(
        self,
        iteration: int,
        plan: AssessmentPlan,
        tasks: List[SecurityTask],
        findings: List[Dict[str, Any]],
        start_time: float,
    ) -> Tuple[bool, str]:
        """Evaluate stopping criteria (Phase 5 §16).

        Returns (should_stop, reason).
        """
        import time

        # 1. Max iterations
        if iteration >= plan.max_iterations:
            return True, f"Maximum iterations reached ({plan.max_iterations})"

        # 2. Max tasks
        if len(tasks) >= plan.max_tasks:
            return True, f"Maximum tasks reached ({plan.max_tasks})"

        # 3. Max runtime
        elapsed = time.time() - start_time
        if elapsed >= plan.max_runtime_seconds:
            return True, f"Maximum runtime reached ({plan.max_runtime_seconds}s)"

        # 4. All planned tasks complete
        pending = [t for t in tasks if t.status in (TaskStatus.PENDING.value,
                                                     TaskStatus.APPROVED.value,
                                                     TaskStatus.RUNNING.value)]
        if not pending:
            return True, "All planned tasks completed"

        # 5. No new high-value findings in last iteration
        # (checked by the decide node using findings from this iteration)

        return False, ""
