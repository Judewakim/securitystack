"""Data model for scan results."""

from dataclasses import asdict, dataclass, field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}


@dataclass(frozen=True)
class Check:
    """A single question we ask about the account, e.g. 'Does root have MFA?'."""

    id: str
    title: str
    severity: str
    category: str
    why: str  # plain-English risk
    fix: str  # plain-English remediation
    fixed_by_securitystack: bool = False  # True if deploying the baseline resolves it
    ok: str = ""  # how a passing result reads, e.g. "Root user has MFA"


@dataclass
class Finding:
    check_id: str
    resource: str
    region: str = "global"
    detail: str = ""


@dataclass
class CheckResult:
    check: Check
    status: str = "PASS"  # PASS | FAIL | UNKNOWN (couldn't evaluate, e.g. access denied)
    findings: list = field(default_factory=list)
    note: str = ""

    def fail(self, resource, region="global", detail=""):
        self.status = "FAIL"
        self.findings.append(Finding(self.check.id, resource, region, detail))

    def unknown(self, note):
        if self.status != "FAIL":
            self.status = "UNKNOWN"
        self.note = (self.note + "; " + note if self.note else note)[:300]

    def to_dict(self):
        d = {
            "id": self.check.id,
            "title": self.check.title,
            "severity": self.check.severity,
            "category": self.check.category,
            "why": self.check.why,
            "fix": self.check.fix,
            "fixedBySecurityStack": self.check.fixed_by_securitystack,
            "ok": self.check.ok or self.check.title,
            "status": self.status,
            "note": self.note,
            "findings": [asdict(f) for f in self.findings[:200]],
            "findingCount": len(self.findings),
        }
        return d
