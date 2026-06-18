"""
Static Analysis Engine — four layers:
Layer 1: MobSF (comprehensive, industry-standard) via Docker API
Layer 2: Local Androguard Static Engine + Semantic MITRE Mapping
Layer 3: Custom YARA rules (C2 patterns, banking trojans)
Layer 4: Androguard APK Diff (repackaging detection)
"""

import re
import subprocess
from pathlib import Path
from typing import Optional

import requests
import dataclasses

from app.config import settings
from app.analysis.apk_analyzer import APKAnalyzer
from app.analysis.semantic_analyzer import SemanticAnalyzer


class StaticAnalyzer:
    """
    Three-layer static analysis engine.
    Works without running the APK — safe against evasion.
    """

    def __init__(self):
        self.mobsf_url = settings.MOBSF_URL
        self.mobsf_key = settings.MOBSF_API_KEY
        self._yara_rules = None

    def full_scan(self, apk_path: str) -> dict:
        """Run all three layers and merge results."""
        results = {
            "mobsf": {},
            "androguard": {},
            "semantic_findings": [],
            "yara_matches": [],
            "repackage_check": {},
            "permissions": [],
            "urls_found": [],
            "c2_candidates": [],
            "summary": {}
        }

        # Layer 1: MobSF
        try:
            results["mobsf"] = self._mobsf_scan(apk_path)
            results["permissions"] = self._extract_permissions(results["mobsf"])
            results["urls_found"] = self._extract_urls(results["mobsf"])
            results["c2_candidates"] = self._filter_c2_candidates(results["urls_found"])
        except Exception as e:
            print(f"[Static] MobSF scan failed: {e}")
            results["mobsf"] = {"error": str(e)}

        # Layer 2: Local Androguard + Semantic MITRE
        try:
            analyzer = APKAnalyzer(apk_path)
            apk_result = analyzer.analyze()
            
            # Convert dataclass to dict, skipping massive lists if needed, but keeping them for now
            results["androguard"] = dataclasses.asdict(apk_result)
            
            sem_analyzer = SemanticAnalyzer()
            sem_findings = sem_analyzer.analyze_components(apk_result)
            sem_findings += sem_analyzer.analyze_strings_semantic(apk_result)
            
            results["semantic_findings"] = [dataclasses.asdict(f) for f in sem_findings]
        except Exception as e:
            print(f"[Static] Androguard local scan failed: {e}")
            results["androguard"] = {"error": str(e)}

        # Layer 3: YARA
        try:
            results["yara_matches"] = self._yara_scan(apk_path)
        except Exception as e:
            print(f"[Static] YARA scan failed: {e}")

        # Layer 4: Repackaging Check
        try:
            results["repackage_check"] = self._repackage_check(apk_path)
        except Exception as e:
            print(f"[Static] Repackage check failed: {e}")
            results["repackage_check"] = {"error": str(e), "is_repackaged": False}

        # Fallback to local Androguard if MobSF failed
        if (not results.get("permissions") or len(results["permissions"]) == 0) and isinstance(results.get("androguard"), dict):
            results["permissions"] = results["androguard"].get("used_permissions", [])
        if (not results.get("urls_found") or len(results["urls_found"]) == 0) and isinstance(results.get("androguard"), dict):
            results["urls_found"] = results["androguard"].get("urls", [])
            results["c2_candidates"] = self._filter_c2_candidates(results["urls_found"])

        # Build summary
        results["summary"] = self._build_summary(results)
        return results

    def _mobsf_scan(self, apk_path: str) -> dict:
        """Upload APK to MobSF, trigger scan, retrieve JSON report."""
        if not self.mobsf_key:
            return {"error": "MobSF API key not configured. Run MobSF and set MOBSF_API_KEY in .env"}

        headers = {"Authorization": self.mobsf_key}

        # Step 1: Upload
        with open(apk_path, "rb") as f:
            upload_resp = requests.post(
                f"{self.mobsf_url}/api/v1/upload",
                files={"file": (Path(apk_path).name, f, "application/octet-stream")},
                headers=headers,
                timeout=120
            )
        if upload_resp.status_code != 200:
            return {"error": f"Upload failed: {upload_resp.status_code}"}

        file_hash = upload_resp.json().get("hash", "")

        # Step 2: Trigger scan
        requests.post(
            f"{self.mobsf_url}/api/v1/scan",
            data={"hash": file_hash, "re_scan": 0, "scan_type": "apk"},
            headers=headers,
            timeout=300
        )

        # Step 3: Get report
        report_resp = requests.post(
            f"{self.mobsf_url}/api/v1/report_json",
            data={"hash": file_hash},
            headers=headers,
            timeout=60
        )
        if report_resp.status_code == 200:
            return report_resp.json()
        return {"error": f"Report failed: {report_resp.status_code}"}

    def _yara_scan(self, apk_path: str) -> list:
        """Run YARA rules against the APK and its embedded files."""
        try:
            from app.analysis.yara_scanner import YARAScanner
        except ImportError:
            print("[Static] yara_scanner module not found, skipping YARA scan")
            return []

        rules_dir = str(Path(__file__).resolve().parent.parent.parent / "yara_rules")
        
        try:
            scanner = YARAScanner(rules_dir)
            matches = scanner.scan_apk(apk_path)
            # The returned matches dict may not have 'severity' at the top level,
            # so let's normalize it to match the old format expectations.
            for m in matches:
                m["severity"] = m.get("meta", {}).get("severity", "MEDIUM")
            return matches
        except Exception as e:
            print(f"[YARA] Error scanning {apk_path}: {e}")
            return []

    def _repackage_check(self, apk_path: str) -> dict:
        """Check if this is a known app repackaged with malware."""
        try:
            from androguard.core.apk import APK
        except ImportError:
            return {"error": "androguard not installed", "is_repackaged": False}

        try:
            a = APK(apk_path)
            pkg = a.get_package()

            # Known legitimate app package names
            KNOWN_LEGIT = {
                "com.sbi.lotusintouch",
                "com.phonepe.app",
                "net.one97.paytm",
                "com.google.android.apps.nbu.paisa.user",
                "com.whatsapp",
                "in.org.npci.upiapp",
            }

            is_known_pkg = pkg in KNOWN_LEGIT
            cert = a.get_certificates_der_v2()
            is_debug_signed = False

            # Check for debug/self-signed certificates
            if cert:
                for c in cert:
                    cert_str = str(c)
                    if "debug" in cert_str.lower() or "android" in cert_str.lower():
                        is_debug_signed = True

            result = {
                "package_name": pkg,
                "is_repackaged": is_known_pkg and is_debug_signed,
                "is_known_package": is_known_pkg,
                "is_debug_signed": is_debug_signed,
            }

            if result["is_repackaged"]:
                result["verdict"] = "REPACKAGED_BANKING_APP"
                result["confidence"] = "HIGH"
                result["severity"] = "CRITICAL"

            return result

        except Exception as e:
            return {"error": str(e), "is_repackaged": False}

    def _extract_permissions(self, mobsf_report: dict) -> list:
        """Extract permissions from MobSF report."""
        perms = mobsf_report.get("permissions", {})
        if isinstance(perms, dict):
            return list(perms.keys())
        elif isinstance(perms, list):
            return perms
        return []

    def _extract_urls(self, mobsf_report: dict) -> list:
        """Extract URLs found in the APK."""
        urls = mobsf_report.get("urls", [])
        if isinstance(urls, list):
            return [u.get("url", u) if isinstance(u, dict) else u for u in urls]
        return []

    def _filter_c2_candidates(self, urls: list) -> list:
        """Filter URLs to likely C2 endpoints."""
        KNOWN_SAFE = {
            "googleapis.com", "gstatic.com", "firebase.io", "firebaseio.com",
            "amazon.com", "cloudflare.com", "akamai.com", "google.com",
            "android.com", "github.com", "microsoft.com", "apple.com",
        }
        SUSPICIOUS_TLDS = ['.ru', '.cn', '.xyz', '.top', '.tk', '.ml', '.cf', '.ga']

        candidates = []
        for url in urls:
            if not isinstance(url, str):
                continue
            if any(safe in url for safe in KNOWN_SAFE):
                continue
            # Flag direct IP URLs
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                candidates.append({"url": url, "reason": "direct_ip_address"})
            elif any(tld in url for tld in SUSPICIOUS_TLDS):
                candidates.append({"url": url, "reason": "suspicious_tld"})
            elif ":" in url.split("/")[-1]:  # Non-standard port
                candidates.append({"url": url, "reason": "non_standard_port"})

        return candidates

    def _build_summary(self, results: dict) -> dict:
        """Build a summary of all static analysis findings."""
        DANGEROUS_PERMS = {
            "android.permission.READ_SMS", "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS", "android.permission.CAMERA",
            "android.permission.READ_CALL_LOG", "android.permission.READ_PHONE_STATE",
        }
        return {
            "dangerous_permissions": [p for p in results["permissions"] if p in DANGEROUS_PERMS],
            "total_permissions": len(results["permissions"]),
            "c2_candidates_count": len(results["c2_candidates"]),
            "yara_hits": len(results["yara_matches"]),
            "critical_yara": [y for y in results["yara_matches"] if y.get("severity") == "CRITICAL"],
            "is_repackaged": results["repackage_check"].get("is_repackaged", False),
            "package_name": results["repackage_check"].get("package_name", "unknown"),
            "semantic_capabilities": list(set(f["capability"] for f in results.get("semantic_findings", []))),
            "obfuscation_score": results.get("androguard", {}).get("obfuscation_score", 0),
        }
