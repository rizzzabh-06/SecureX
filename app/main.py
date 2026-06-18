"""
FastAPI Application Server — REST API + WebSocket for the SecureX.
Serves the backend API consumed by the Next.js frontend.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from app.config import settings
from app.database import db
from app.pipeline.orchestrator import pipeline
from app.ai.agents import agents
from app.ai.rag_engine import rag_engine
from app.threat_intel.intel import threat_intel

# === App Setup ===
app = FastAPI(
    title="SecureX",
    description="AI-Powered Malware Forensics Platform",
    version="4.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections for progress updates
active_connections: dict[str, WebSocket] = {}


@app.get("/")
async def root_redirect():
    """Redirect root access to API docs."""
    return RedirectResponse(url="/docs")


# === Health Check ===
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "4.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "database": "connected",
            "rag_samples": rag_engine.get_count(),
        }
    }


# === Analysis Endpoints ===

@app.post("/api/v1/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    """Upload an APK and start the full analysis pipeline."""
    if not file.filename.endswith(".apk"):
        raise HTTPException(400, "File must be an APK (.apk)")

    content = await file.read()
    if len(content) < 100:
        raise HTTPException(400, "File is too small to be a valid APK")

    # Run analysis in background
    case_id = str(uuid.uuid4())[:8]

    async def progress_cb(data):
        ws = active_connections.get(data.get("case_id"))
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                pass

    # Start analysis as a background task
    asyncio.create_task(_run_analysis(content, file.filename, case_id, progress_cb))

    return {"message": "Analysis started", "case_id": case_id, "status": "queued"}


async def _run_analysis(content: bytes, filename: str, case_id: str, progress_cb):
    """Background analysis task."""
    try:
        # Buffer to allow the frontend WebSocket to connect before blasting messages
        await asyncio.sleep(1.5)
        
        result = await pipeline.run_full_analysis(
            apk_bytes=content,
            filename=filename,
            case_id=case_id,
            progress_callback=progress_cb
        )
        return result
    except Exception as e:
        print(f"[API] Analysis error: {e}")
        return {"error": str(e)}


@app.post("/api/v1/analyze/url")
async def analyze_url(data: dict):
    """Download APK from URL and analyze it."""
    url = data.get("url")
    if not url:
        raise HTTPException(400, "URL is required")

    try:
        from app.ingestion.ingest import IngestAPK
        ingestor = IngestAPK()
        ingestion = await ingestor.from_url(url)

        with open(ingestion["path"], "rb") as f:
            content = f.read()

        async def progress_cb(data):
            pass  # No WebSocket for URL analysis yet

        result = await pipeline.run_full_analysis(
            apk_bytes=content,
            filename=Path(ingestion["path"]).name,
            source="url_download",
            source_url=url,
            progress_callback=progress_cb
        )
        return result
    except Exception as e:
        raise HTTPException(400, str(e))


# === Report Endpoints ===

@app.get("/api/v1/cases")
async def list_cases(limit: int = Query(20, ge=1, le=100)):
    """List recent analysis cases."""
    cases = db.list_cases(limit)
    return {"cases": cases}


@app.get("/api/v1/report/{case_id}")
async def get_report(case_id: str):
    """Get full analysis report for a case."""
    findings = db.get_findings(case_id)
    if not findings:
        raise HTTPException(404, f"Case {case_id} not found")

    report = findings.get("findings", findings)
    if isinstance(report, str):
        report = json.loads(report)
    return report


@app.get("/api/v1/report/{case_id}/pdf")
async def download_pdf(case_id: str):
    """Download the PDF forensic report."""
    findings = db.get_findings(case_id)
    if not findings:
        raise HTTPException(404, f"Case {case_id} not found")

    report = findings.get("findings", findings)
    if isinstance(report, str):
        report = json.loads(report)

    pdf_path = report.get("pdf_path", "")
    if pdf_path and Path(pdf_path).exists():
        return FileResponse(pdf_path, media_type="application/pdf",
                          filename=f"forensic_report_{case_id}.pdf")

    # Generate on the fly
    from app.reporting.pdf_generator import generate_report_pdf
    try:
        pdf_path = generate_report_pdf(report)
        return FileResponse(pdf_path, media_type="application/pdf",
                          filename=f"forensic_report_{case_id}.pdf")
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {e}")


@app.get("/api/v1/status/{case_id}")
async def get_status(case_id: str):
    """Check analysis progress."""
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    return case


# === Chat Endpoint ===

@app.post("/api/v1/chat/{case_id}")
async def chat_with_case(case_id: str, data: dict):
    """Ask questions about a completed analysis."""
    question = data.get("question", "")
    if not question:
        raise HTTPException(400, "Question is required")

    findings = db.get_findings(case_id)
    if not findings:
        raise HTTPException(404, f"Case {case_id} not found")

    report = findings.get("findings", findings)
    if isinstance(report, str):
        report = json.loads(report)

    answer = agents.chat_about_case(question, report)
    return {"answer": answer, "case_id": case_id}


# === Non-Technical Summary ===

@app.post("/api/v1/explain/{case_id}")
async def explain_case(case_id: str):
    """Generate non-technical explanation for police/judges."""
    findings = db.get_findings(case_id)
    if not findings:
        raise HTTPException(404, f"Case {case_id} not found")

    report = findings.get("findings", findings)
    if isinstance(report, str):
        report = json.loads(report)

    summary = agents.explain_for_non_technical(report)
    return {"summary": summary, "case_id": case_id}


# === Threat Intel ===

@app.get("/api/v1/intel/hash/{sha256}")
async def check_hash(sha256: str):
    """Check a file hash against VirusTotal."""
    return threat_intel.check_hash(sha256)


@app.get("/api/v1/intel/ip/{ip}")
async def check_ip(ip: str):
    """Check an IP against VirusTotal + AbuseIPDB."""
    return threat_intel.check_ip(ip)


# === WebSocket for Real-Time Progress ===

@app.websocket("/api/v1/ws/{case_id}")
async def websocket_endpoint(websocket: WebSocket, case_id: str):
    await websocket.accept()
    active_connections[case_id] = websocket
    try:
        while True:
            # Keep connection alive, receive any client messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.pop(case_id, None)


# === RAG Stats ===

@app.get("/api/v1/rag/stats")
async def rag_stats():
    """Get RAG database statistics."""
    return {"sample_count": rag_engine.get_count()}


# === Demo Data Endpoint ===

@app.get("/api/v1/demo/report")
async def demo_report():
    """Return a demo report for UI development."""
    return {
        "case_id": "demo-001",
        "package_name": "com.fake.sbi.yono",
        "apk_sha256": "a3f9c2d1e5b87fa2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
        "apk_md5": "7d4a2b9c3e8f1a2b3c4d5e6f",
        "size_bytes": 4847293,
        "source": "file_upload",
        "status": "complete",
        "threat_score": 94,
        "classification": "CRITICAL",
        "malware_family": "SpyNote RAT / Banking Trojan",
        "static_analysis": {
            "summary": {
                "dangerous_permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.CAMERA",
                    "android.permission.READ_CONTACTS"
                ],
                "total_permissions": 23,
                "c2_candidates_count": 3,
                "yara_hits": 2,
                "critical_yara": [
                    {"rule": "Android_SpyNote_C2_Beacon", "severity": "CRITICAL"},
                    {"rule": "Android_Banker_SMS_Intercept", "severity": "CRITICAL"}
                ],
                "is_repackaged": True,
                "package_name": "com.fake.sbi.yono"
            },
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_CALL_LOG",
                "android.permission.RECEIVE_BOOT_COMPLETED"
            ],
            "yara_matches": [
                {"rule": "Android_SpyNote_C2_Beacon", "severity": "CRITICAL",
                 "meta": {"description": "SpyNote RAT — C2 connection pattern", "family": "SpyNote"}},
                {"rule": "Android_Banker_SMS_Intercept", "severity": "CRITICAL",
                 "meta": {"description": "OTP-stealing banker — aborts incoming SMS broadcast"}}
            ],
            "c2_candidates": [
                {"url": "http://185.220.101.45:4444", "reason": "direct_ip_address"},
                {"url": "https://malware-c2.xyz/beacon", "reason": "suspicious_tld"},
                {"url": "http://91.134.10.22:8443/gate", "reason": "direct_ip_address"}
            ]
        },
        "threat_intel": {
            "hash_check": {
                "known": True, "malicious": 41, "total_engines": 70,
                "detection_ratio": "41/70",
                "families": ["SpyNote", "AndroidOS/SpyAgent", "Trojan.Android.Banker"],
                "threat_level": "CRITICAL"
            },
            "ip_checks": [
                {"ip": "185.220.101.45", "composite_risk": 92,
                 "vt": {"malicious": 15, "country": "DE", "asn": "AS12345 BulletProof Hosting"},
                 "abuseipdb": {"confidence": 89, "reports": 47, "isp": "BulletProof GmbH", "country": "DE"}},
                {"ip": "91.134.10.22", "composite_risk": 67,
                 "vt": {"malicious": 8, "country": "FR", "asn": "AS16276 OVH"},
                 "abuseipdb": {"confidence": 45, "reports": 12, "isp": "OVH SAS", "country": "FR"}}
            ],
            "overall_threat_level": "CRITICAL"
        },
        "ai_analysis": {
            "code_analysis": {
                "purpose": "Banking credential theft via overlay attack",
                "hidden_indicators": ["Hardcoded C2 IP 185.220.101.45:4444", "AES key in assets/config.dat"],
                "malware_family_hint": "SpyNote RAT variant",
                "severity": "CRITICAL",
                "simple_explanation": "This code creates a fake banking login screen that appears over the real SBI YONO app to steal passwords and OTP codes."
            },
            "behavior_context": {
                "behavior_narrative": "The app mimics the SBI YONO banking application. Upon installation, it registers a broadcast receiver to intercept incoming SMS messages, specifically targeting OTP codes. It establishes a persistent connection to 185.220.101.45:4444, transmitting device info, GPS coordinates, and intercepted SMS content every 57 seconds.",
                "mitre_techniques": [
                    {"id": "T1412", "name": "Capture SMS Messages"},
                    {"id": "T1430", "name": "Location Tracking"},
                    {"id": "T1437.001", "name": "C2 over HTTPS"},
                    {"id": "T1633.001", "name": "Virtualization/Sandbox Evasion"}
                ],
                "malware_classification": "Mobile RAT / SMS Stealer / Spyware",
                "data_at_risk": ["SMS/OTP codes", "GPS location", "Contact list", "Call logs"]
            },
            "risk_assessment": {
                "score": 94,
                "classification": "CRITICAL",
                "chain_of_reasoning": "This application was assigned a risk score of 94/100 based on the following chain of evidence: (1) Static analysis revealed hardcoded C2 endpoint 185.220.101.45:4444 in the decompiled DexClassLoader routine, consistent with SpyNote RAT's known network signature. (2) YARA rule 'Android_SpyNote_C2_Beacon' matched with CRITICAL severity. (3) The app uses SMS interception (abortBroadcast on SMS_RECEIVED) to steal OTP codes. (4) VirusTotal: 41/70 engines flagged as SpyNote.Android. (5) The C2 IP 185.220.101.45 is hosted on a known bulletproof hosting provider with 47 prior abuse reports on AbuseIPDB. (6) The app is a repackaged version of the legitimate SBI YONO banking app with a different signing certificate.",
                "recommendations": [
                    "Block IP 185.220.101.45 on all network perimeters immediately",
                    "File abuse report with the hosting provider (BulletProof GmbH, Germany)",
                    "Issue advisory to all SBI YONO users about this impersonation campaign"
                ],
                "mitre_ttps": ["T1412", "T1430", "T1437.001", "T1633.001", "T1407"],
                "confidence": "HIGH",
                "malware_family": "SpyNote RAT / Banking Trojan"
            },
            "non_technical_summary": "This app was designed to look exactly like the real SBI YONO banking application. When a customer installs it, it secretly reads all their incoming text messages, specifically looking for OTP codes sent by their bank. Every minute, it sends the stolen OTP codes, along with the customer's exact GPS location, to a criminal's server located in Germany. This server has already been reported for criminal activity by 47 other organizations worldwide. The app also takes a copy of the customer's entire contact list. Any customer who installed this app has likely had their banking credentials stolen and should immediately change their passwords and contact their bank."
        },
        "rag_results": {
            "similar_samples": [
                {"label": "SpyNote 3.2", "similarity_pct": 94.2, "match_strength": "HIGH"},
                {"label": "AndroidBanker", "similarity_pct": 78.5, "match_strength": "MEDIUM"},
                {"label": "SpyAgent", "similarity_pct": 72.1, "match_strength": "MEDIUM"}
            ],
            "best_match": "SpyNote 3.2",
            "similarity_pct": 94.2
        },
        "c2_infrastructure": [
            {"ip": "185.220.101.45", "country": "DE", "asn": "AS12345 BulletProof Hosting",
             "composite_risk": 92, "beacon_interval_seconds": 57},
            {"ip": "91.134.10.22", "country": "FR", "asn": "AS16276 OVH",
             "composite_risk": 67, "beacon_interval_seconds": 120}
        ],
        "mitre_ttps": ["T1412", "T1430", "T1437.001", "T1633.001", "T1407", "T1406"],
        "custody_chain": {
            "case_id": "demo-001",
            "entry_count": 6,
            "integrity": "VERIFIED"
        },
        "created_at": "2026-06-14T00:00:00Z",
        "completed_at": "2026-06-14T00:04:32Z"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
