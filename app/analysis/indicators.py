"""
Threat Indicator Scoring Engine
Evaluates APK analysis results against known malware patterns.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ThreatIndicator:
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    score: int
    evidence: list[str] = field(default_factory=list)
    mitre_technique: str = ""


@dataclass
class ThreatAssessment:
    risk_score: int = 0          # 0-100
    risk_level: str = "CLEAN"    # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
    indicators: list[ThreatIndicator] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    yara_matches: list[dict] = field(default_factory=list)
    permission_score: int = 0
    behavior_score: int = 0
    obfuscation_score: int = 0
    network_score: int = 0


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 0,
}

RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "CLEAN"),
]

KNOWN_MALWARE_RECEIVER_ACTIONS = {
    "android.provider.Telephony.SMS_RECEIVED": "SMS interception",
    "android.intent.action.BOOT_COMPLETED": "persistence on boot",
    "android.net.conn.CONNECTIVITY_CHANGE": "network state monitoring",
    "android.intent.action.PACKAGE_ADDED": "app install monitoring",
    "android.intent.action.PACKAGE_REMOVED": "app removal monitoring",
    "android.telephony.action.PHONE_STATE_CHANGED": "call interception",
}


class ApkResultWrapper:
    """Adapts the static_analyzer dict output to the object interface expected by IndicatorEngine."""
    class MockComponent:
        def __init__(self, name_or_dict):
            if isinstance(name_or_dict, dict):
                self.name = name_or_dict.get("name", str(name_or_dict))
                self.exported = name_or_dict.get("exported", True)
                self.intent_filters = name_or_dict.get("intent_filters", [])
                self.permissions = name_or_dict.get("permissions", [])
            else:
                self.name = str(name_or_dict)
                self.exported = True
                self.intent_filters = []
                self.permissions = []

    def __init__(self, data: dict):
        andro = data.get("androguard", {})
        mobsf = data.get("mobsf", {})
        
        self.used_permissions = data.get("permissions", []) or andro.get("used_permissions", [])
        
        # Mobsf provides activities/services/receivers as lists of dicts or strings
        self.activities = [self.MockComponent(c) for c in (mobsf.get("activities", []) or andro.get("activities", []))]
        self.receivers = [self.MockComponent(c) for c in (mobsf.get("receivers", []) or andro.get("receivers", []))]
        self.services = [self.MockComponent(c) for c in (mobsf.get("services", []) or andro.get("services", []))]
        self.providers = [self.MockComponent(c) for c in (mobsf.get("providers", []) or andro.get("providers", []))]
        
        self.suspicious_api_calls = andro.get("suspicious_api_calls", [])
        self.obfuscation_score = andro.get("obfuscation_score", 0)
        self.obfuscation_indicators = andro.get("obfuscation_indicators", [])
        
        self.urls = data.get("urls_found", []) or andro.get("urls", [])
        self.domains = []
        self.ips = []
        
        import re
        for u in self.urls:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(u))
            if ip_match:
                self.ips.append(ip_match.group(1))
            else:
                domain_match = re.search(r'https?://([^/:\s]+)', str(u))
                if domain_match:
                    self.domains.append(domain_match.group(1))
                    
        self.all_strings = andro.get("all_strings", [])
        self.embedded_files = andro.get("embedded_files", [])
        self.native_libs = andro.get("native_libs", [])

class IndicatorEngine:
    """Evaluates APK analysis results and generates threat indicators."""

    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.permissions_db = {}
        self.patterns_db = {}
        self._load_rules()

    def _load_rules(self):
        """Load YAML rule files."""
        perms_file = self.rules_dir / "permissions.yaml"
        patterns_file = self.rules_dir / "suspicious_patterns.yaml"

        if perms_file.exists():
            with open(perms_file) as f:
                self.permissions_db = yaml.safe_load(f) or {}

        if patterns_file.exists():
            with open(patterns_file) as f:
                self.patterns_db = yaml.safe_load(f) or {}

    def assess(self, raw_apk_result, intel_results=None, frida_events=None) -> ThreatAssessment:
        """Run full threat assessment on APK analysis result."""
        assessment = ThreatAssessment()
        
        # Adapt dictionary to object if necessary
        if isinstance(raw_apk_result, dict):
            apk_result = ApkResultWrapper(raw_apk_result)
        else:
            apk_result = raw_apk_result

        self._check_permissions(apk_result, assessment)
        self._check_suspicious_components(apk_result, assessment)
        self._check_suspicious_apis(apk_result, assessment)
        self._check_network_iocs(apk_result, assessment)
        self._check_strings(apk_result, assessment)
        self._check_obfuscation(apk_result, assessment)
        self._check_embedded_threats(apk_result, assessment)
        self._check_permission_combinations(apk_result, assessment)

        # ----------------------------------------------------
        # DETERMINISTIC HEURISTIC SCORING SYSTEM (Out of 100)
        # ----------------------------------------------------
        
        # 1. Threat Intel (VirusTotal) (Max 50 points)
        # +5 points per detection engine
        vt_score = 0
        if intel_results:
            vt_detections = intel_results.get("hash_check", {}).get("malicious", 0)
            vt_score = min(vt_detections * 5, 50)
            
            # If VT found engines, add threat indicators
            if vt_detections > 0:
                assessment.indicators.append(ThreatIndicator(
                    name=f"Threat Intelligence: {vt_detections} VT Flag(s)",
                    description=f"APK flagged as malicious by {vt_detections} engine(s) on VirusTotal",
                    severity="CRITICAL" if vt_detections >= 10 else "HIGH" if vt_detections >= 5 else "MEDIUM",
                    category="Threat Intel",
                    score=vt_score,
                    evidence=[f"VT Detection Ratio: {intel_results.get('hash_check', {}).get('detection_ratio', '0/0')}"],
                ))
                
                # Capture family attributions if any
                families = intel_results.get("hash_check", {}).get("families", [])
                for f in families:
                    if f not in assessment.malware_families:
                        assessment.malware_families.append(f)

        # 2. YARA Matches (Max 40 points)
        # +20 for Critical rules, +15 for High, +5 for Medium
        yara_score = 0
        yara_matches = []
        if isinstance(raw_apk_result, dict):
            yara_matches = raw_apk_result.get("yara_matches", [])
            
        for match in yara_matches:
            severity = match.get("severity", match.get("meta", {}).get("severity", "MEDIUM")).upper()
            if severity == "CRITICAL":
                yara_score += 20
            elif severity == "HIGH":
                yara_score += 15
            elif severity == "MEDIUM":
                yara_score += 5
            else:
                yara_score += 2
                
            # Add threat indicator for YARA hits
            assessment.indicators.append(ThreatIndicator(
                name=f"YARA Match: {match.get('rule')}",
                description=match.get("meta", {}).get("description", f"Matched YARA rule {match.get('rule')}"),
                severity=severity,
                category="Static Rules",
                score=20 if severity == "CRITICAL" else 15 if severity == "HIGH" else 5,
                evidence=match.get("strings", []),
            ))
        yara_score = min(yara_score, 40)

        # 3. Dangerous Permissions (Max 20 points)
        # +5 points for each highly sensitive permission
        perm_score = 0
        DANGEROUS_PERMS = {
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE"
        }
        used_perms = apk_result.used_permissions
        sensitive_perms_found = [p for p in used_perms if p in DANGEROUS_PERMS]
        perm_score = min(len(sensitive_perms_found) * 5, 20)

        # 4. Dynamic Analysis Events (Max 40 points)
        # +20 points for critical runtime actions like dynamic_code_load or crypto/SMS operations
        dynamic_score = 0
        if frida_events:
            for event in frida_events:
                ev_type = event.get("type", "")
                if ev_type == "dynamic_code_load":
                    dynamic_score += 20
                    assessment.indicators.append(ThreatIndicator(
                        name="Dynamic Code Loading Detected at Runtime",
                        description=f"Frida intercepted dynamic class/dex loading: {event.get('dexPath', '')}",
                        severity="CRITICAL",
                        category="Dynamic Behavior",
                        score=20,
                        evidence=[event.get("dexPath", "")],
                    ))
                elif ev_type == "sms_send":
                    dynamic_score += 20
                    assessment.indicators.append(ThreatIndicator(
                        name="SMS Sending Attempt Blocked",
                        description=f"Frida intercepted SMS sending to {event.get('destination', '')} with text: {event.get('body', '')}",
                        severity="CRITICAL",
                        category="Dynamic Behavior",
                        score=20,
                        evidence=[f"Dest: {event.get('destination')}"],
                    ))
                elif ev_type == "location_read":
                    dynamic_score += 20
                    assessment.indicators.append(ThreatIndicator(
                        name="Location Access Intercepted",
                        description=f"Frida intercepted runtime location request. Coordinates: {event.get('lat')}, {event.get('lon')}",
                        severity="HIGH",
                        category="Dynamic Behavior",
                        score=20,
                        evidence=[f"Lat: {event.get('lat')}, Lon: {event.get('lon')}"],
                    ))
                elif ev_type in ("tcp_connect", "http_request"):
                    dynamic_score += 10
                    evidence_str = event.get("url", f"{event.get('host')}:{event.get('port')}")
                    assessment.indicators.append(ThreatIndicator(
                        name="Runtime Network Activity",
                        description=f"Frida intercepted network traffic: {evidence_str}",
                        severity="MEDIUM",
                        category="Dynamic Behavior",
                        score=10,
                        evidence=[evidence_str],
                    ))
                elif ev_type in ("native_lib_load", "native_lib_load0"):
                    dynamic_score += 10
                    assessment.indicators.append(ThreatIndicator(
                        name="Dynamic Native Library Load",
                        description=f"Frida intercepted loadLibrary call for: {event.get('libname')}",
                        severity="MEDIUM",
                        category="Dynamic Behavior",
                        score=10,
                        evidence=[event.get("libname", "")],
                    ))
            dynamic_score = min(dynamic_score, 40)

        # 5. Obfuscation (+10 points if obfuscation_score > 5)
        obfuscation_score = 0
        if apk_result.obfuscation_score > 5:
            obfuscation_score = 10

        # Calculate final combined threat score, capped at 100
        total_score = min(vt_score + yara_score + perm_score + dynamic_score + obfuscation_score, 100)
        
        # Override rules-based scores in assessment
        assessment.permission_score = perm_score
        assessment.behavior_score = min(yara_score + dynamic_score, 100)
        assessment.obfuscation_score = obfuscation_score
        assessment.network_score = vt_score
        assessment.risk_score = total_score
        
        # Risk level
        for threshold, level in RISK_LEVELS:
            if assessment.risk_score >= threshold:
                assessment.risk_level = level
                break

        # Collect MITRE techniques from indicators
        assessment.mitre_techniques = list({
            ind.mitre_technique
            for ind in assessment.indicators
            if ind.mitre_technique
        })

        # Capture YARA matches in the assessment
        assessment.yara_matches = yara_matches

        return assessment

    def _check_permissions(self, apk_result, assessment: ThreatAssessment):
        """Check permissions against danger database."""
        if not self.permissions_db:
            return

        dangerous = self.permissions_db.get("dangerous_permissions", {})
        critical_perms = dangerous.get("critical", [])

        perm_set = set(apk_result.used_permissions)

        for perm_rule in critical_perms:
            perm = perm_rule["permission"]
            if perm in perm_set:
                assessment.indicators.append(ThreatIndicator(
                    name=f"Dangerous Permission: {perm.split('.')[-1]}",
                    description=perm_rule["description"],
                    severity="HIGH" if perm_rule["score"] >= 8 else "MEDIUM",
                    category="Permissions",
                    score=perm_rule["score"] * 3,
                    evidence=[perm],
                    mitre_technique=self._perm_to_mitre(perm),
                ))

    def _check_permission_combinations(self, apk_result, assessment: ThreatAssessment):
        """Check dangerous permission combinations."""
        if not self.permissions_db:
            return

        combos = self.permissions_db.get("dangerous_permissions", {}).get("suspicious_combinations", [])
        perm_set = set(apk_result.used_permissions)

        for combo in combos:
            combo_perms = combo["permissions"]
            if all(p in perm_set for p in combo_perms):
                assessment.indicators.append(ThreatIndicator(
                    name=f"Dangerous Permission Combo: {combo['threat']}",
                    description=combo["description"],
                    severity=combo["severity"],
                    category="Permissions",
                    score=SEVERITY_WEIGHTS[combo["severity"]] * 5,
                    evidence=combo_perms,
                ))
                if combo["threat"] not in assessment.malware_families:
                    assessment.malware_families.append(combo["threat"])

    def _check_suspicious_components(self, apk_result, assessment: ThreatAssessment):
        """Check Android components for red flags."""
        # Exported components without permissions
        for activity in apk_result.activities:
            if activity.exported and not activity.permissions:
                assessment.indicators.append(ThreatIndicator(
                    name="Exported Activity Without Permission",
                    description=f"Activity '{activity.name}' is exported without permission protection",
                    severity="LOW",
                    category="Components",
                    score=10,
                    evidence=[activity.name],
                ))

        # Suspicious receiver actions
        for receiver in apk_result.receivers:
            for intent in receiver.intent_filters:
                for action, description in KNOWN_MALWARE_RECEIVER_ACTIONS.items():
                    if action in intent:
                        assessment.indicators.append(ThreatIndicator(
                            name=f"Suspicious Broadcast: {action.split('.')[-1]}",
                            description=f"Receiver listens for {description}: {action}",
                            severity="MEDIUM",
                            category="Components",
                            score=15,
                            evidence=[receiver.name, action],
                            mitre_technique="T1624",
                        ))

        # Device admin receiver
        for receiver in apk_result.receivers:
            if "DeviceAdminReceiver" in receiver.name or any(
                "device_admin" in f.lower() for f in receiver.intent_filters
            ):
                assessment.indicators.append(ThreatIndicator(
                    name="Device Admin Receiver",
                    description="App registers as Device Administrator - can lock/wipe device",
                    severity="CRITICAL",
                    category="Persistence",
                    score=50,
                    evidence=[receiver.name],
                    mitre_technique="T1629",
                ))
                if "Ransomware" not in assessment.malware_families:
                    assessment.malware_families.append("Ransomware/Persistent Malware")

        # Accessibility service
        for service in apk_result.services:
            if "Accessibility" in service.name or "accessibility" in service.name.lower():
                assessment.indicators.append(ThreatIndicator(
                    name="Accessibility Service",
                    description="App implements Accessibility Service - can intercept UI events, simulate clicks, overlay attacks",
                    severity="HIGH",
                    category="Overlay/Keylog",
                    score=35,
                    evidence=[service.name],
                    mitre_technique="T1417",
                ))

    def _check_suspicious_apis(self, apk_result, assessment: ThreatAssessment):
        """Check for suspicious API usage patterns."""
        category_counts = {}
        category_evidence = {}

        for entry in apk_result.suspicious_api_calls:
            cat = entry["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1
            if cat not in category_evidence:
                category_evidence[cat] = []
            if len(category_evidence[cat]) < 3:
                category_evidence[cat].append(f"{entry['api']} (in {entry['class']})")

        severity_map = {
            "Dynamic Code Loading": ("HIGH", 30, "T1544"),
            "Device Admin": ("CRITICAL", 40, "T1629"),
            "Accessibility Service": ("HIGH", 30, "T1417"),
            "Notification Interception": ("HIGH", 25, "T1412"),
            "SMS Operations": ("HIGH", 25, "T1582"),
            "Package Installation": ("HIGH", 30, "T1475"),
            "Native Execution": ("HIGH", 20, "T1203"),
            "Reflection": ("MEDIUM", 15, "T1407"),
            "Audio Recording": ("HIGH", 25, "T1429"),
            "Location Tracking": ("MEDIUM", 20, "T1430"),
            "Camera Access": ("MEDIUM", 20, "T1513"),
            "Account Credentials": ("HIGH", 25, "T1634"),
            "Window Overlay": ("HIGH", 25, "T1417"),
            "Cryptography": ("LOW", 5, ""),
            "Network Communication": ("INFO", 2, ""),
        }

        for cat, count in category_counts.items():
            if cat not in severity_map:
                continue
            severity, base_score, mitre = severity_map[cat]
            if severity == "INFO" and count < 3:
                continue

            assessment.indicators.append(ThreatIndicator(
                name=f"Suspicious API: {cat}",
                description=f"App uses {count} {cat} API call(s)",
                severity=severity,
                category="API Behavior",
                score=base_score,
                evidence=category_evidence.get(cat, [])[:3],
                mitre_technique=mitre,
            ))

    def _check_network_iocs(self, apk_result, assessment: ThreatAssessment):
        """Check network indicators of compromise."""
        # Hardcoded IPs (not private)
        if apk_result.ips:
            assessment.indicators.append(ThreatIndicator(
                name="Hardcoded IP Addresses",
                description=f"App contains {len(apk_result.ips)} hardcoded IP address(es) - possible C2",
                severity="HIGH",
                category="Network",
                score=20 + len(apk_result.ips) * 3,
                evidence=apk_result.ips[:5],
                mitre_technique="T1571",
            ))

        # Suspicious domains
        suspicious_tlds = [".onion", ".tk", ".top", ".xyz", ".pw", ".cc", ".su"]
        suspicious_services = ["ngrok", "duckdns", "no-ip", "ddns", "telegram", "discord"]

        sus_domains = []
        for domain in apk_result.domains:
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                sus_domains.append(domain)
            elif any(svc in domain.lower() for svc in suspicious_services):
                sus_domains.append(domain)

        if sus_domains:
            assessment.indicators.append(ThreatIndicator(
                name="Suspicious C2 Domains",
                description=f"App contacts suspicious domains: {', '.join(sus_domains[:3])}",
                severity="HIGH",
                category="Network",
                score=25 + len(sus_domains) * 5,
                evidence=sus_domains[:5],
                mitre_technique="T1102",
            ))

        # Telegram bot C2
        tg_urls = [u for u in apk_result.urls if "api.telegram.org" in u or "t.me/" in u]
        if tg_urls:
            assessment.indicators.append(ThreatIndicator(
                name="Telegram Bot C2",
                description="App communicates with Telegram Bot API - common C2 channel",
                severity="HIGH",
                category="Network",
                score=30,
                evidence=tg_urls[:3],
                mitre_technique="T1102",
            ))

        # Discord webhook
        dc_urls = [u for u in apk_result.urls if "discord.com/api/webhooks" in u or "discordapp.com/api/webhooks" in u]
        if dc_urls:
            assessment.indicators.append(ThreatIndicator(
                name="Discord Webhook Exfiltration",
                description="App uses Discord webhooks for data exfiltration/C2",
                severity="HIGH",
                category="Network",
                score=28,
                evidence=dc_urls[:2],
                mitre_technique="T1102",
            ))

    def _check_strings(self, apk_result, assessment: ThreatAssessment):
        """Check strings for malware indicators."""
        all_strings_joined = "\n".join(apk_result.all_strings[:2000])

        # Root/su paths
        root_patterns = ["/system/bin/su", "/system/xbin/su", "superuser", "SuperSU"]
        root_found = [p for p in root_patterns if p in all_strings_joined]
        if root_found:
            assessment.indicators.append(ThreatIndicator(
                name="Root/Superuser Access Attempts",
                description="App attempts to gain root/superuser privileges",
                severity="HIGH",
                category="Privilege Escalation",
                score=25,
                evidence=root_found,
                mitre_technique="T1626",
            ))

        # Anti-analysis
        emu_patterns = ["goldfish", "genymotion", "qemu", "bluestacks", "nox"]
        emu_found = [p for p in emu_patterns if p.lower() in all_strings_joined.lower()]
        if emu_found:
            assessment.indicators.append(ThreatIndicator(
                name="Emulator Detection",
                description="App checks for emulator/sandbox environment",
                severity="MEDIUM",
                category="Evasion",
                score=15,
                evidence=emu_found,
                mitre_technique="T1633",
            ))

        # Ransomware strings
        ransom_patterns = ["bitcoin", "BTC", "monero", "XMR", "decrypt your files",
                          "your files are encrypted", "payment", "ransom"]
        ransom_found = [p for p in ransom_patterns if p.lower() in all_strings_joined.lower()]
        if len(ransom_found) >= 2:
            assessment.indicators.append(ThreatIndicator(
                name="Ransomware Strings",
                description="App contains ransomware-related strings",
                severity="CRITICAL",
                category="Ransomware",
                score=50,
                evidence=ransom_found,
                mitre_technique="T1486",
            ))
            if "Ransomware" not in assessment.malware_families:
                assessment.malware_families.append("Ransomware")

        # Keylogging/overlay
        overlay_patterns = ["overlay", "keylog", "keystroke", "TYPE_APPLICATION_OVERLAY"]
        overlay_found = [p for p in overlay_patterns if p.lower() in all_strings_joined.lower()]
        if overlay_found:
            assessment.indicators.append(ThreatIndicator(
                name="Overlay/Keylogger Strings",
                description="App contains overlay or keylogging related strings",
                severity="HIGH",
                category="Overlay/Keylog",
                score=25,
                evidence=overlay_found,
                mitre_technique="T1417",
            ))

    def _check_obfuscation(self, apk_result, assessment: ThreatAssessment):
        """Report obfuscation indicators."""
        if apk_result.obfuscation_score >= 3:
            severity = "HIGH" if apk_result.obfuscation_score >= 6 else "MEDIUM"
            assessment.indicators.append(ThreatIndicator(
                name=f"Code Obfuscation (score: {apk_result.obfuscation_score}/10)",
                description="App uses code obfuscation to evade static analysis",
                severity=severity,
                category="Obfuscation",
                score=apk_result.obfuscation_score * 4,
                evidence=apk_result.obfuscation_indicators[:3],
                mitre_technique="T1406",
            ))

    def _check_embedded_threats(self, apk_result, assessment: ThreatAssessment):
        """Check for embedded malicious files."""
        # Embedded APKs
        embedded_apks = [f for f in apk_result.embedded_files if f["name"].endswith(".apk")]
        if embedded_apks:
            assessment.indicators.append(ThreatIndicator(
                name="Embedded APK Files",
                description=f"App contains {len(embedded_apks)} embedded APK(s) - dropper pattern",
                severity="HIGH",
                category="Dropper",
                score=30,
                evidence=[f["name"] for f in embedded_apks[:3]],
                mitre_technique="T1475",
            ))

        # Embedded JAR/DEX
        extra_dex = [f for f in apk_result.embedded_files
                     if f["name"].endswith(".dex") and f["name"] != "classes.dex"]
        if extra_dex:
            assessment.indicators.append(ThreatIndicator(
                name="Embedded DEX Payloads",
                description=f"App contains {len(extra_dex)} additional DEX file(s) - possible packed payload",
                severity="MEDIUM",
                category="Dropper",
                score=20,
                evidence=[f["name"] for f in extra_dex[:3]],
                mitre_technique="T1544",
            ))

        # Native libraries (potential shellcode)
        if len(apk_result.native_libs) > 4:
            assessment.indicators.append(ThreatIndicator(
                name="Excessive Native Libraries",
                description=f"App contains {len(apk_result.native_libs)} native .so libraries",
                severity="LOW",
                category="Native Code",
                score=10,
                evidence=apk_result.native_libs[:3],
            ))

    def _perm_to_mitre(self, permission: str) -> str:
        """Map permission to MITRE ATT&CK technique."""
        mapping = {
            "READ_SMS": "T1412",
            "RECEIVE_SMS": "T1412",
            "SEND_SMS": "T1582",
            "RECORD_AUDIO": "T1429",
            "CAMERA": "T1513",
            "ACCESS_FINE_LOCATION": "T1430",
            "ACCESS_COARSE_LOCATION": "T1430",
            "READ_CONTACTS": "T1636",
            "BIND_DEVICE_ADMIN": "T1629",
            "BIND_ACCESSIBILITY_SERVICE": "T1417",
            "INSTALL_PACKAGES": "T1475",
            "GET_ACCOUNTS": "T1634",
            "READ_CALL_LOG": "T1433",
            "PROCESS_OUTGOING_CALLS": "T1433",
            "CALL_PHONE": "T1433",
            "PACKAGE_USAGE_STATS": "T1418",
            "READ_PHONE_STATE": "T1426",
            "MODIFY_PHONE_STATE": "T1426",
        }
        for key, val in mapping.items():
            if key in permission:
                return val
        return ""
