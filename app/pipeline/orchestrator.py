"""
Pipeline Orchestrator — coordinates all analysis stages end-to-end.
Runs stages in sequence with progress tracking via WebSocket.
"""

import asyncio
import json
import uuid
import re
from datetime import datetime, timezone
from typing import Optional, Callable

from app.database import db
from app.ingestion.ingest import IngestAPK
from app.analysis.static_analyzer import StaticAnalyzer
from app.threat_intel.intel import threat_intel
from app.ai.agents import agents
from app.ai.rag_engine import rag_engine
from app.reporting.chain_of_custody import ChainOfCustody
from app.reporting.pdf_generator import generate_report_pdf
from app.analysis.indicators import IndicatorEngine


class AnalysisPipeline:
    """
    End-to-end analysis pipeline.
    Coordinates: Ingest → Static → ThreatIntel → AI → RAG → Report
    """

    def __init__(self):
        self.ingestor = IngestAPK()
        self.static_analyzer = StaticAnalyzer()
        self.indicator_engine = IndicatorEngine("app/rules")

    async def run_full_analysis(
        self,
        apk_bytes: bytes,
        filename: str,
        case_id: Optional[str] = None,
        source: str = "file_upload",
        source_url: str = None,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Run the complete analysis pipeline on an APK.
        Returns a full report dict.
        """
        if not case_id:
            case_id = str(uuid.uuid4())[:8]
        report = {
            "case_id": case_id,
            "status": "running",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        async def update_progress(pct: int, stage: str, msg: str):
            if progress_callback:
                await progress_callback({
                    "case_id": case_id,
                    "progress_pct": pct,
                    "status": stage,
                    "message": msg
                })

        try:
            # === Stage 1: Ingestion ===
            await update_progress(5, "ingesting", "📥 Ingesting APK...")
            ingestion = self.ingestor.from_file(apk_bytes, filename)
            report.update({
                "apk_sha256": ingestion["sha256"],
                "apk_md5": ingestion["md5"],
                "size_bytes": ingestion["size_bytes"],
                "source": source,
                "source_url": source_url,
                "apk_path": ingestion["path"],
            })

            # Start chain of custody
            custody = ChainOfCustody(case_id, ingestion["sha256"], ingestion["size_bytes"])
            custody.log("HASH_COMPUTED", sha256=ingestion["sha256"], md5=ingestion["md5"])

            # Save case to DB
            db.create_case({
                "id": case_id,
                "apk_sha256": ingestion["sha256"],
                "size_bytes": ingestion["size_bytes"],
                "source": source,
                "status": "running"
            })

            # === Stage 2: Static Analysis ===
            await update_progress(10, "static_analysis", "[Static] Unpacking APK and decompiling Dalvik bytecode...")
            await update_progress(15, "static_analysis", "🔍 Running static analysis (MobSF + YARA)...")
            static_results = self.static_analyzer.full_scan(ingestion["path"])
            report["static_analysis"] = static_results
            report["package_name"] = static_results.get("summary", {}).get("package_name", "unknown")
            custody.log("STATIC_ANALYSIS_COMPLETE",
                        permissions=len(static_results.get("permissions", [])),
                        yara_hits=len(static_results.get("yara_matches", [])))
            await update_progress(35, "static_analysis", f"🔍 Static analysis complete — {len(static_results.get('yara_matches', []))} YARA hits")

            # === Stage 3: Threat Intelligence ===
            await update_progress(40, "threat_intel", "[Network] Extracting C2 domains and hardcoded IP addresses...")
            await update_progress(45, "threat_intel", "🌐 Querying threat intelligence APIs...")
            c2_candidates = static_results.get("c2_candidates", [])
            c2_ips = []
            c2_domains = []
            for c in c2_candidates:
                url = c.get("url", "")
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', url)
                if ip_match:
                    c2_ips.append(ip_match.group(1))
                else:
                    # Extract domain from URL
                    domain_match = re.search(r'https?://([^/:\s]+)', url)
                    if domain_match:
                        c2_domains.append(domain_match.group(1))

            intel_results = threat_intel.enrich_all(
                sha256=ingestion["sha256"],
                ips=c2_ips,
                domains=c2_domains
            )
            report["threat_intel"] = intel_results
            report["c2_infrastructure"] = intel_results.get("ip_checks", [])
            custody.log("THREAT_INTEL_COMPLETE",
                        vt_known=intel_results.get("hash_check", {}).get("known", False))
            await update_progress(60, "threat_intel", f"🌐 Threat intelligence enrichment complete: {len(c2_ips)} IPs scanned.")

            # === Stage 3.5: Dynamic Analysis (Frida) ===
            await update_progress(61, "dynamic_analysis", "[Dynamic] Initializing sandbox environment...")
            await update_progress(62, "dynamic_analysis", "📱 Running dynamic analysis (Frida)...")
            from app.analysis.dynamic_analyzer import DynamicAnalyzer
            dynamic_analyzer = DynamicAnalyzer()
            frida_events = []
            if dynamic_analyzer.is_frida_available():
                pkg_name = report.get("package_name", "unknown")
                await update_progress(63, "dynamic_analysis", f"[Dynamic] Compiling Frida agent payload...")
                await update_progress(64, "dynamic_analysis", f"[Dynamic] Connected to Emulator/Device. Installing {pkg_name}...")
                await update_progress(65, "dynamic_analysis", f"[Dynamic] Spawning & resuming target process. Hooking API calls...")
                if pkg_name and pkg_name != "unknown":
                    frida_events = dynamic_analyzer.start_analysis(pkg_name, apk_path=str(report["apk_path"]), duration_seconds=15)
                else:
                    frida_events = [{"type": "info", "message": "Package name unknown, skipping Frida spawn"}]
            else:
                frida_events = [{"type": "info", "message": "Frida Python package not installed on host, skipping instrumentation"}]
            
            await update_progress(66, "dynamic_analysis", f"[Dynamic] Dynamic analysis finished. Intercepted {len(frida_events)} events.")
            # Filter out internal 'agent_ready' housekeeping event from reported findings
            findings_events = [ev for ev in frida_events if ev.get("type") != "agent_ready"]
            report["dynamic_analysis"] = {"events": findings_events}
            custody.log("DYNAMIC_ANALYSIS_COMPLETE", events_count=len(findings_events))

            # === Stage 4: AI Analysis ===
            await update_progress(67, "ai_analysis", "[AI] Loading Threat Context and Behavior Data into LLM memory...")
            await update_progress(68, "ai_analysis", "🧠 GenAI analyzing findings...")

            ai_results = {}

            # Run indicator engine for rule-based MITRE mapping and risk assessment
            assessment = self.indicator_engine.assess(static_results, intel_results=intel_results, frida_events=frida_events)
            # Convert indicators to dicts for JSON serialization
            indicator_dicts = [
                {
                    "name": i.name, "severity": i.severity, "category": i.category,
                    "evidence": i.evidence, "mitre_technique": i.mitre_technique
                } for i in assessment.indicators
            ]

            # Agent 1: Code analysis (if we have decompiled code)
            code_snippets = static_results.get("mobsf", {}).get("code_analysis", {})
            if code_snippets and isinstance(code_snippets, dict):
                # Provide the full findings for AI analysis
                snippet_text = json.dumps(code_snippets)
                ai_results["code_analysis"] = agents.analyze_code(snippet_text)
            else:
                # Provide a rich structured payload to the AI agent
                analysis_input = {
                    "permissions": static_results.get("permissions", []),
                    "c2_candidates": [c.get("url", "") for c in c2_candidates],
                    "threat_indicators": indicator_dicts,
                    "malware_families": assessment.malware_families,
                    "yara_matches": static_results.get("yara_matches", []),
                    "semantic_findings": static_results.get("semantic_findings", {})
                }
                ai_results["code_analysis"] = agents.analyze_code(json.dumps(analysis_input))

            await update_progress(76, "ai_analysis", "🧠 AI behavior analysis...")

            # Agent 2: Behavior context
            ai_results["behavior_context"] = agents.contextualize_behavior(
                frida_events=frida_events,
                network_summary={
                    "c2_ips": c2_ips,
                    "c2_domains": c2_domains,
                    "vt_detections": intel_results.get("hash_check", {}).get("detection_ratio", "0/0")
                }
            )

            # Agent 3: Risk scoring
            all_findings = {
                "static": {
                    "permissions": static_results.get("permissions", []),
                    "yara_matches": static_results.get("yara_matches", []),
                    "semantic_findings": static_results.get("semantic_findings", {})
                },
                "indicator_engine_assessment": {
                    "risk_score": assessment.risk_score,
                    "risk_level": assessment.risk_level,
                    "indicators": indicator_dicts,
                    "malware_families": assessment.malware_families
                },
                "threat_intel": {
                    "vt_detections": intel_results.get("hash_check", {}).get("detection_ratio", "0/0"),
                    "vt_families": intel_results.get("hash_check", {}).get("families", []),
                    "vt_top_detections": intel_results.get("hash_check", {}).get("top_detections", []),
                    "ip_risks": [c.get("composite_risk", 0) for c in intel_results.get("ip_checks", [])]
                },
                "behavior": ai_results.get("behavior_context", {}),
            }
            ai_results["risk_assessment"] = agents.generate_risk_score(
                all_findings=all_findings,
                deterministic_score=assessment.risk_score,
                deterministic_classification=assessment.risk_level
            )

            # Agent 4: Non-technical summary
            ai_results["non_technical_summary"] = agents.explain_for_non_technical(all_findings)

            report["ai_analysis"] = ai_results
            await update_progress(85, "ai_analysis", "🧠 AI analysis complete")

            # Save indicators to report for the PDF
            report["threat_indicators"] = indicator_dicts
            
            # Extract threat score directly from our deterministic IndicatorEngine assessment
            risk = ai_results.get("risk_assessment", {})
            report["threat_score"] = assessment.risk_score
            report["classification"] = assessment.risk_level
            
            # The AI only provides the family attribution and MITRE TTPs
            report["malware_family"] = risk.get("malware_family", assessment.malware_families[0] if assessment.malware_families else "")
            
            # Merge MITRE techniques
            ai_mitre = risk.get("mitre_ttps", [])
            engine_mitre = assessment.mitre_techniques
            report["mitre_ttps"] = list(set(ai_mitre + engine_mitre))

            custody.log("AI_ANALYSIS_COMPLETE",
                        threat_score=report["threat_score"],
                        classification=report["classification"])

            # === Stage 5: RAG Memory Search ===
            await update_progress(88, "rag_search", "🔗 RAG memory search...")
            rag_features = {
                "permissions": static_results.get("permissions", []),
                "dangerous_permissions": static_results.get("summary", {}).get("dangerous_permissions", []),
                "behaviors": ai_results.get("behavior_context", {}).get("malware_classification", ""),
                "c2_patterns": [c.get("url", "") for c in c2_candidates],
            }
            rag_results = rag_engine.find_similar(rag_features)
            report["rag_results"] = {
                "similar_samples": rag_results,
                "best_match": rag_results[0]["label"] if rag_results else None,
                "similarity_pct": rag_results[0]["similarity_pct"] if rag_results else 0,
            }

            # Store this analysis in RAG for future reference
            rag_engine.add_sample(
                sample_id=ingestion["sha256"],
                features=rag_features,
                label=report.get("malware_family", report.get("classification", "unknown"))
            )

            # === Stage 6: Generate Report ===
            await update_progress(92, "reporting", "📄 Generating forensic report...")
            custody.log("REPORT_GENERATION_STARTED")
            report["custody_chain"] = custody.export()

            # Generate PDF
            try:
                pdf_path = generate_report_pdf(report)
                report["pdf_path"] = pdf_path
                custody.log("PDF_GENERATED", path=pdf_path)
            except Exception as e:
                print(f"[Pipeline] PDF generation failed: {e}")
                report["pdf_path"] = ""

            # Update custody chain with final state
            report["custody_chain"] = custody.export()

            # === Complete ===
            report["status"] = "complete"
            report["completed_at"] = datetime.now(timezone.utc).isoformat()

            # Save to DB
            db.update_case(case_id, {
                "status": "complete",
                "package_name": report.get("package_name", ""),
                "threat_score": report.get("threat_score", 0),
                "classification": report.get("classification", "CLEAN"),
                "malware_family": report.get("malware_family", ""),
            })
            db.save_findings(case_id, report)

            await update_progress(100, "complete", f"✅ Analysis complete — Score: {report['threat_score']}/100 {report['classification']}")

        except Exception as e:
            report["status"] = "failed"
            report["error"] = str(e)
            db.update_case(case_id, {"status": "failed", "error": str(e)})
            await update_progress(0, "failed", f"❌ Analysis failed: {str(e)}")

        return report


# Singleton
pipeline = AnalysisPipeline()
