from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Asset:
    name: str
    type: str
    exposure: str
    notes: str


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    evidence: str
    impact: str
    recommendation: str
    affected_assets: List[str]


@dataclass(frozen=True)
class AttackPath:
    name: str
    difficulty: str
    steps: List[str]
    impact: str
    blocked_by: str


@dataclass(frozen=True)
class RoadmapItem:
    priority: str
    action: str
    expected_outcome: str


@dataclass(frozen=True)
class AnalysisReport:
    architecture_summary: str
    assets: List[Asset]
    findings: List[Finding]
    attack_paths: List[AttackPath]
    blast_radius: List[str]
    fix_roadmap: List[RoadmapItem]
    verification_checklist: List[str]
    safer_target_architecture: List[str]
    risk_score: int
    risk_label: str
