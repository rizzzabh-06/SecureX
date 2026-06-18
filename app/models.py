"""
Pydantic models for request/response validation across the API.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    INGESTING = "ingesting"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    THREAT_INTEL = "threat_intel"
    AI_ANALYSIS = "ai_analysis"
    RAG_SEARCH = "rag_search"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# === Request Models ===

class URLAnalysisRequest(BaseModel):
    url: str
    options: Optional[Dict[str, bool]] = None


class ChatRequest(BaseModel):
    question: str
    case_id: str


# === Response Models ===

class IngestionResult(BaseModel):
    case_id: str
    path: str
    sha256: str
    md5: str
    size_bytes: int
    source: str
    source_url: Optional[str] = None


class YARAMatch(BaseModel):
    rule: str
    tags: List[str] = []
    meta: Dict[str, Any] = {}
    severity: str = "MEDIUM"


class StaticAnalysisResult(BaseModel):
    mobsf: Dict[str, Any] = {}
    yara_matches: List[YARAMatch] = []
    repackage_check: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}


class ThreatIntelResult(BaseModel):
    hash_check: Dict[str, Any] = {}
    ip_checks: List[Dict[str, Any]] = []
    domain_checks: List[Dict[str, Any]] = []
    url_scans: List[Dict[str, Any]] = []


class AIAnalysisResult(BaseModel):
    code_analysis: Dict[str, Any] = {}
    behavior_context: Dict[str, Any] = {}
    risk_assessment: Dict[str, Any] = {}
    non_technical_summary: str = ""


class RAGResult(BaseModel):
    similar_samples: List[Dict[str, Any]] = []
    best_match: Optional[str] = None
    similarity_pct: float = 0.0


class AnalysisProgress(BaseModel):
    case_id: str
    status: AnalysisStatus
    progress_pct: int = 0
    current_stage: str = ""
    message: str = ""


class FullReport(BaseModel):
    case_id: str
    package_name: str = ""
    apk_sha256: str = ""
    apk_md5: str = ""
    size_bytes: int = 0
    source: str = ""
    status: AnalysisStatus = AnalysisStatus.COMPLETE
    threat_score: int = 0
    classification: ThreatLevel = ThreatLevel.CLEAN
    malware_family: str = ""

    static_analysis: StaticAnalysisResult = StaticAnalysisResult()
    threat_intel: ThreatIntelResult = ThreatIntelResult()
    ai_analysis: AIAnalysisResult = AIAnalysisResult()
    rag_results: RAGResult = RAGResult()

    c2_infrastructure: List[Dict[str, Any]] = []
    mitre_ttps: List[str] = []
    custody_chain: Dict[str, Any] = {}

    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class CaseListItem(BaseModel):
    id: str
    package_name: str = ""
    threat_score: int = 0
    classification: str = "CLEAN"
    status: str = "pending"
    created_at: str = ""
