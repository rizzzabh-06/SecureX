"""
Multi-source Threat Intelligence using ONLY free API tiers.
All calls are cached to avoid hitting rate limits during demo.

Free daily limits:
- VirusTotal: 500 lookups/day
- AbuseIPDB: 1,000 checks/day
- MalwareBazaar: Unlimited
"""

import re
import requests
from functools import lru_cache
from typing import Optional

from app.config import settings


class ThreatIntelLayer:
    """
    Multi-source threat intelligence enrichment.
    Converts raw indicators into actionable intelligence.
    """

    def __init__(self):
        self.vt_key = settings.VIRUSTOTAL_API_KEY
        self.abuse_key = settings.ABUSEIPDB_API_KEY

    def enrich_all(self, sha256: str, ips: list = None, domains: list = None) -> dict:
        """Run all enrichment checks and return combined result."""
        result = {
            "hash_check": {},
            "ip_checks": [],
            "domain_checks": [],
            "overall_threat_level": "CLEAN"
        }

        # Check file hash
        if sha256:
            result["hash_check"] = self.check_hash(sha256)

        # Check IPs
        for ip in (ips or []):
            ip_str = ip if isinstance(ip, str) else ip.get("ip", ip.get("url", ""))
            # Extract IP from URL if needed
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip_str)
            if ip_match:
                result["ip_checks"].append(self.check_ip(ip_match.group(1)))

        # Check domains
        for domain in (domains or []):
            d = domain if isinstance(domain, str) else domain.get("domain", "")
            if d:
                result["domain_checks"].append(self.check_domain(d))

        # Determine overall threat level
        result["overall_threat_level"] = self._compute_overall_threat(result)
        return result

    @lru_cache(maxsize=512)
    def check_hash(self, sha256: str) -> dict:
        """Check if APK hash is known malware on VirusTotal."""
        if not self.vt_key:
            return {"error": "VirusTotal API key not configured", "known": False}

        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self.vt_key},
                timeout=15
            )
            if r.status_code == 404:
                return {"known": False, "detections": 0, "total_engines": 0}

            if r.status_code != 200:
                return {"error": f"VT API error: {r.status_code}", "known": False}

            data = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)

            # Get malware family names and top detections
            families = []
            PRIORITY_VENDORS = {"Kaspersky", "ESET-NOD32", "BitDefender", "Sophos", "Symantec",
                                 "TrendMicro", "DrWeb", "Avast", "CrowdStrike", "Microsoft"}
            malicious_results = []
            
            for vendor, v in data.get("last_analysis_results", {}).items():
                if v.get("category") == "malicious":
                    result_name = v.get("result", "")
                    if result_name:
                        families.append(result_name)
                    malicious_results.append({
                        "vendor": vendor,
                        "result": result_name
                    })
                    
            malicious_results.sort(key=lambda x: (0 if x["vendor"] in PRIORITY_VENDORS else 1, x["vendor"]))

            return {
                "known": True,
                "malicious": malicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}",
                "families": list(set(families))[:10],
                "top_detections": malicious_results[:10],
                "threat_level": (
                    "CRITICAL" if malicious > 20 else
                    "HIGH" if malicious > 5 else
                    "MEDIUM" if malicious > 0 else
                    "CLEAN"
                ),
                "tags": data.get("tags", []),
                "type_description": data.get("type_description", ""),
                "popular_threat_name": data.get("popular_threat_classification", {}).get("suggested_threat_label", "")
            }

        except requests.exceptions.Timeout:
            return {"error": "VirusTotal timeout", "known": False}
        except Exception as e:
            return {"error": str(e), "known": False}

    @lru_cache(maxsize=512)
    def check_ip(self, ip: str) -> dict:
        """Check IP against VirusTotal + AbuseIPDB."""
        result = {"ip": ip}

        # VirusTotal IP check
        if self.vt_key:
            try:
                vt = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.vt_key},
                    timeout=10
                )
                if vt.status_code == 200:
                    attr = vt.json()["data"]["attributes"]
                    result["vt"] = {
                        "malicious": attr.get("last_analysis_stats", {}).get("malicious", 0),
                        "country": attr.get("country", "Unknown"),
                        "asn": attr.get("as_owner", "Unknown"),
                        "tags": attr.get("tags", [])
                    }
            except Exception:
                pass

        # AbuseIPDB check
        if self.abuse_key:
            try:
                abuse = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=10
                )
                if abuse.status_code == 200:
                    d = abuse.json()["data"]
                    result["abuseipdb"] = {
                        "confidence": d.get("abuseConfidenceScore", 0),
                        "reports": d.get("totalReports", 0),
                        "isp": d.get("isp", "Unknown"),
                        "usage_type": d.get("usageType", "Unknown"),
                        "country": d.get("countryCode", "Unknown"),
                    }
            except Exception:
                pass

        # Composite risk
        vt_score = min(result.get("vt", {}).get("malicious", 0) * 4, 40)
        abuse_score = result.get("abuseipdb", {}).get("confidence", 0) // 2
        result["composite_risk"] = min(vt_score + abuse_score, 100)
        result["is_tor"] = "tor" in result.get("vt", {}).get("tags", [])

        return result

    @lru_cache(maxsize=512)
    def check_domain(self, domain: str) -> dict:
        """Check domain age and reputation."""
        if not self.vt_key:
            return {"domain": domain, "error": "VT key not set"}

        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self.vt_key},
                timeout=10
            )
            if r.status_code == 200:
                attr = r.json()["data"]["attributes"]
                creation = attr.get("creation_date")
                age_days = None
                if creation:
                    from datetime import datetime
                    age_days = (datetime.now() - datetime.fromtimestamp(creation)).days

                return {
                    "domain": domain,
                    "malicious_votes": attr.get("total_votes", {}).get("malicious", 0),
                    "domain_age_days": age_days,
                    "newly_registered": age_days < 30 if age_days else None,
                    "categories": list(attr.get("categories", {}).values()),
                    "registrar": attr.get("registrar", "Unknown"),
                }
        except Exception:
            pass
        return {"domain": domain}

    def check_malwarebazaar(self, sha256: str) -> dict:
        """Check MalwareBazaar (unlimited free API)."""
        try:
            r = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "hash_not_found":
                    return {"known": False}
                sample = data.get("data", [{}])[0]
                return {
                    "known": True,
                    "file_type": sample.get("file_type", ""),
                    "tags": sample.get("tags", []),
                    "signature": sample.get("signature", ""),
                    "reporter": sample.get("reporter", ""),
                }
        except Exception:
            pass
        return {"known": False}

    def _compute_overall_threat(self, result: dict) -> str:
        """Compute an overall threat level from all enrichment data."""
        hash_level = result.get("hash_check", {}).get("threat_level", "CLEAN")
        if hash_level == "CRITICAL":
            return "CRITICAL"

        max_ip_risk = max(
            [c.get("composite_risk", 0) for c in result.get("ip_checks", [])] or [0]
        )
        if max_ip_risk > 70:
            return "CRITICAL" if hash_level in ("HIGH", "CRITICAL") else "HIGH"
        if max_ip_risk > 40:
            return "HIGH" if hash_level != "CLEAN" else "MEDIUM"
        if hash_level != "CLEAN":
            return hash_level

        return "CLEAN"


# Singleton
threat_intel = ThreatIntelLayer()
