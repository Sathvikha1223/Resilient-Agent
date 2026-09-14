"""
Phase 3: Core Engine -- rule-based anomaly detection + explanation layer.
"""
from collections import Counter
from dataclasses import dataclass, field
from typing import List


@dataclass
class Baseline:
    files_per_minute: float
    avg_write_kb: float


DEFAULT_BASELINE = Baseline(files_per_minute=15.0, avg_write_kb=20.0)


@dataclass
class ActivityWindow:
    process_name: str
    files_modified: int
    minutes_elapsed: float
    total_write_kb: float
    extensions_before: Counter = field(default_factory=Counter)
    extensions_after: Counter = field(default_factory=Counter)
    sample_entropy: float = 0.0
    entropy_delta: float = 0.0
    pid: int = None

    @property
    def files_per_minute(self):
        return self.files_modified / max(self.minutes_elapsed, 0.001)

    @property
    def avg_write_kb(self):
        return self.total_write_kb / max(self.files_modified, 1)


@dataclass
class RuleResult:
    name: str
    triggered: bool
    weight: float
    detail: str


def run_rules(window: ActivityWindow, baseline: Baseline) -> List[RuleResult]:
    results = []

    rate_multiplier = window.files_per_minute / max(baseline.files_per_minute, 0.001)
    rate_triggered = rate_multiplier >= 20
    results.append(RuleResult(
        name="rate_spike", triggered=rate_triggered,
        weight=0.45 if rate_triggered else 0.0,
        detail=f"File modification rate is {rate_multiplier:.0f}x the process baseline "
               f"({window.files_per_minute:.0f}/min vs baseline {baseline.files_per_minute:.0f}/min)."
    ))

    new_extensions = set(window.extensions_after) - set(window.extensions_before)
    ext_changed_count = sum(window.extensions_after[e] for e in new_extensions)
    ext_triggered = ext_changed_count >= max(5, 0.5 * window.files_modified)
    results.append(RuleResult(
        name="extension_change", triggered=ext_triggered,
        weight=0.35 if ext_triggered else 0.0,
        detail=f"{ext_changed_count} files changed to unfamiliar extensions "
               f"({', '.join(sorted(new_extensions)) or 'none'})."
    ))

    TRUSTED_HIGH_ENTROPY_EXT = {
        "zip", "gz", "tar", "7z", "rar", "mp4", "mov", "avi", "mkv",
        "mp3", "jpg", "jpeg", "png", "gif", "docx", "xlsx", "pptx", "pdf",
    }
    after_exts = set(window.extensions_after.keys())
    is_trusted_format = bool(after_exts) and after_exts.issubset(TRUSTED_HIGH_ENTROPY_EXT)
    extension_changed = bool(set(window.extensions_after) - set(window.extensions_before))

    if is_trusted_format and not extension_changed:
        entropy_triggered = False
        entropy_detail = (
            f"Entropy is {window.sample_entropy:.2f}, but files are an already-compressed/binary "
            f"format ({', '.join(sorted(after_exts))}) with no extension change -- expected, not anomalous."
        )
    elif window.entropy_delta >= 0.4 and window.sample_entropy >= 0.85:
        entropy_triggered = True
        entropy_detail = (
            f"File entropy jumped by {window.entropy_delta:.2f} to {window.sample_entropy:.2f} "
            f"vs its own prior state -- consistent with plaintext overwritten by encrypted content."
        )
    elif window.entropy_delta == 0.0 and window.sample_entropy >= 0.85:
        entropy_triggered = True
        entropy_detail = (
            f"Sampled entropy is {window.sample_entropy:.2f} (no prior baseline for this file -- "
            f"absolute-threshold match, not a confirmed jump)."
        )
    else:
        entropy_triggered = False
        entropy_detail = (
            f"Entropy is {window.sample_entropy:.2f}, delta {window.entropy_delta:.2f} -- not a significant jump."
        )

    results.append(RuleResult(
        name="high_entropy_content", triggered=entropy_triggered,
        weight=0.20 if entropy_triggered else 0.0, detail=entropy_detail
    ))

    return results


def compute_risk_score(rule_results: List[RuleResult]) -> float:
    score = sum(r.weight for r in rule_results if r.triggered)
    return round(min(score, 1.0) * 100, 1)


@dataclass
class Explanation:
    summary: str
    root_cause: str
    recommendation: str


def explain(window: ActivityWindow, rule_results: List[RuleResult], risk_score: float) -> Explanation:
    triggered = [r for r in rule_results if r.triggered]

    if not triggered:
        return Explanation(
            summary="Activity is within normal bounds for this process.",
            root_cause="No rules triggered; behaviour matches the established baseline.",
            recommendation="No action needed. Continue routine snapshotting."
        )

    reasons = " ".join(r.detail for r in triggered)
    lead_rule = max(triggered, key=lambda r: r.weight)
    cause_map = {
        "rate_spike": "an abnormal burst of file-modification activity",
        "extension_change": "a bulk rename pattern typical of encryption tools",
        "high_entropy_content": "file contents that now resemble encrypted/random data",
    }
    root_cause_lead = cause_map.get(lead_rule.name, "abnormal activity")

    if risk_score >= 80:
        severity = "high-confidence ransomware-like event"
        recommendation = (
            f"Immediately isolate process '{window.process_name}' if possible, and protect the "
            f"latest known-good snapshot before restoring."
        )
    elif risk_score >= 40:
        severity = "moderate-risk anomaly"
        recommendation = (
            f"Monitor process '{window.process_name}' closely and take an out-of-cycle snapshot now."
        )
    else:
        severity = "low-risk anomaly"
        recommendation = "Log the event and continue monitoring; no immediate action required."

    summary = (
        f"Process '{window.process_name}' triggered a {severity} "
        f"(risk score {risk_score}/100), primarily due to {root_cause_lead}."
    )
    return Explanation(summary=summary, root_cause=f"Contributing factors: {reasons}", recommendation=recommendation)
