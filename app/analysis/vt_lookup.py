"""
VirusTotal API v3 integration (optional — requires VT_API_KEY env var).
Provides official detection counts and family names to cross-validate analysis.
"""
import os
import time
import requests
from dataclasses import dataclass, field


@dataclass
class VTResult:
    sha256: str = ""
    detection_ratio: str = ""        # e.g. "38/72"
    malicious_count: int = 0
    suspicious_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    family_names: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    threat_label: str = ""           # crowdsourced label
    top_detections: list[dict] = field(default_factory=list)
    suspicious_detections: list[dict] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    times_submitted: int = 0
    unique_sources: int = 0
    file_type: str = ""              # e.g. "Android"
    meaningful_name: str = ""        # most common submitted filename
    file_names: list[str] = field(default_factory=list)
    sandbox_verdicts: list[dict] = field(default_factory=list)
    url: str = ""
    error: str = ""


def _fmt_ts(ts) -> str:
    """Convert Unix timestamp to YYYY-MM-DD string."""
    if not ts:
        return ""
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return str(ts)


class VTLookup:
    """VirusTotal v3 API client."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
        self.available = bool(self.api_key)

    def lookup(self, sha256: str) -> VTResult:
        """Look up a file hash on VirusTotal."""
        result = VTResult(sha256=sha256, url=f"https://www.virustotal.com/gui/file/{sha256}")

        if not self.available:
            result.error = "VT_API_KEY not set — skipping VirusTotal lookup"
            return result

        try:
            resp = requests.get(
                f"{self.BASE}/files/{sha256}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )

            if resp.status_code == 404:
                result.error = "Hash not found on VirusTotal"
                return result
            if resp.status_code == 429:
                result.error = "VirusTotal rate limit hit"
                return result
            if resp.status_code != 200:
                result.error = f"VT API error: {resp.status_code}"
                return result

            data = resp.json().get("data", {}).get("attributes", {})

            stats = data.get("last_analysis_stats", {})
            result.malicious_count = stats.get("malicious", 0)
            result.suspicious_count = stats.get("suspicious", 0)
            result.undetected_count = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())
            result.detection_ratio = f"{result.malicious_count}/{result.total_engines}"

            # Family names from popular threat classification
            result.threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "")
            family_info = data.get("popular_threat_classification", {}).get("popular_threat_name", [])
            result.family_names = [f.get("value", "") for f in family_info]

            result.tags = data.get("tags", [])
            result.first_seen = _fmt_ts(data.get("first_submission_date"))
            result.last_seen = _fmt_ts(data.get("last_analysis_date"))
            result.times_submitted = data.get("times_submitted", 0)
            result.unique_sources = data.get("unique_sources", 0)
            result.file_type = data.get("type_description", "") or data.get("magic", "")
            result.meaningful_name = data.get("meaningful_name", "")
            result.file_names = data.get("names", [])[:10]

            # Top detections (sorted by vendor reputation)
            PRIORITY_VENDORS = {"Kaspersky", "ESET-NOD32", "BitDefender", "Sophos", "Symantec",
                                 "TrendMicro", "DrWeb", "Avast", "CrowdStrike", "Microsoft",
                                 "McAfee", "Malwarebytes", "F-Secure", "G-Data", "Fortinet"}
            analyses = data.get("last_analysis_results", {})
            malicious = []
            suspicious = []
            for vendor, info in analyses.items():
                cat = info.get("category", "")
                entry = {"vendor": vendor, "result": info.get("result", "") or "", "category": cat}
                if cat == "malicious":
                    malicious.append(entry)
                elif cat == "suspicious":
                    suspicious.append(entry)
            malicious.sort(key=lambda x: (0 if x["vendor"] in PRIORITY_VENDORS else 1, x["vendor"]))
            suspicious.sort(key=lambda x: (0 if x["vendor"] in PRIORITY_VENDORS else 1, x["vendor"]))
            result.top_detections = malicious[:20]
            result.suspicious_detections = suspicious[:10]

            # Sandbox verdicts
            verdicts = data.get("sandbox_verdicts", {})
            result.sandbox_verdicts = [
                {"sandbox": name, "verdict": v.get("category", ""), "malware_names": v.get("malware_names", [])}
                for name, v in verdicts.items()
                if v.get("category") in ("malicious", "suspicious")
            ][:8]

        except requests.exceptions.Timeout:
            result.error = "VirusTotal request timed out"
        except Exception as e:
            result.error = f"VT lookup error: {e}"

        return result
