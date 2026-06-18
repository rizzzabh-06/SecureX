"""
Semantic Component Name Analyzer
Extracts capabilities from service/activity/receiver names even without AI.
This is often the most revealing part of static analysis for poorly-obfuscated malware.
"""
import math
import re
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class SemanticFinding:
    component: str           # service / activity / receiver / class
    name: str                # component full name
    capability: str          # inferred capability
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    mitre: str               # T-code
    confidence: int          # 0-100


# Keyword → (capability, severity, MITRE)
COMPONENT_PATTERNS = {
    # RAT / Remote Control
    r"ServiceRAT|RATService|RemoteAccess|RemoteControl": ("Remote Access Trojan (RAT)", "CRITICAL", "T1430"),
    r"ServiceCommands?|CommandHandler|C2Service|BotService|CommandService": ("C2 Command Execution", "CRITICAL", "T1417"),
    r"ServiceVNC|VNCService|SendRequestImageVNC|ScreenStream": ("VNC/Live Screen Remote Control", "CRITICAL", "T1513"),
    r"ServiceForward|TunnelService|SocksService|ProxyService|ForwardingTunel": ("SOCKS Proxy / Traffic Tunneling", "HIGH", "T1572"),

    # Overlay / Injection
    r"ServiceInjection|InjectionService|OverlayService|ActivityInjection|PushInjection": ("Overlay Injection Attack", "CRITICAL", "T1417"),
    r"ActivityScreenLocker?|LookScreen|ServiceLookScreen|ScreenLock": ("Screen Locker / Ransomware Module", "CRITICAL", "T1486"),

    # SMS / Telephony
    r"ServiceHeadlessSms|HeadlessSMS|SilentSms|ServiceSms|SendSms|SMSService": ("Covert SMS Sending", "CRITICAL", "T1582"),
    r"ServiceDeleteSMS|DeleteSms|SmsDelete|EraseSms": ("SMS Deletion (anti-forensic)", "HIGH", "T1582"),
    r"ReceiverMms|MmsReceiver|SmsReceiver|ReceiverSMS": ("SMS/MMS Interception", "CRITICAL", "T1412"),

    # Accessibility
    r"ServiceAccessibility|AccessibilityService|accessibilityImage|AccesService": ("Accessibility Service Abuse", "CRITICAL", "T1417"),

    # Screenshot / Screen
    r"ServiceScreenshot|ScreenshotService|ActivityScreenshot|TakeScreenshot": ("Screen Capture", "HIGH", "T1513"),

    # Location / GPS
    r"ServiceGeolocation|GeolocationService|ServiceGPS|GPSService|LocationService": ("Location Tracking", "HIGH", "T1430"),

    # Audio / Camera
    r"ServiceAudio|AudioRecord|Microphone|MicService": ("Audio Recording / Surveillance", "CRITICAL", "T1429"),
    r"ServiceCamera|CameraService|TakePhoto": ("Camera Capture", "HIGH", "T1513"),

    # File / Data Exfil
    r"ServiceFindFiles?|FileSearch|FileFinder|FileGrabber": ("File Enumeration & Theft", "HIGH", "T1533"),
    r"ServiceUpload|UploadService|Exfil|DataSend": ("Data Exfiltration", "HIGH", "T1646"),

    # USSD / Banking
    r"ActivityStartUSSD|USSDRunner|USSDExecutor": ("USSD Code Execution (bank account wipe)", "CRITICAL", "T1582"),
    r"ActivityGetNumber|GetPhoneNumber|PhoneCapture": ("Phone Number Harvesting", "MEDIUM", "T1426"),

    # Notification
    r"ServiceModuleNotification|NotificationListener|NotifInterceptor|NotificationListenerService": ("Notification Interception (OTP theft)", "HIGH", "T1412"),

    # Persistence
    r"ReceiverBoot|BootReceiver|StartOnBoot|AutoStart": ("Boot Persistence", "HIGH", "T1624"),
    r"ReceiverAlarm|AlarmReceiver|KeepAlive|WatchdogService|PollingService": ("Alarm-based Persistence", "MEDIUM", "T1624"),
    r"EncryptionService|DecryptionService|FileCrypt|FileEncrypt": ("File Encryption (Ransomware)", "CRITICAL", "T1486"),

    # Device Admin
    r"DeviceAdmin|AdminReceiver|PolicyManager": ("Device Administrator Abuse", "CRITICAL", "T1629"),

    # Evasion
    r"ActivityPlayProtect|PlayProtect|DisableAV|KillAntivirus": ("Play Protect / AV Bypass", "HIGH", "T1629"),
    r"ServiceHide|HideIcon|SelfHide|HideLauncher": ("Icon/Launcher Hiding (stealth)", "HIGH", "T1516"),

    # Pedometer / Sensor abuse
    r"ServicePedometer|PedometerService": ("Sensor/Pedometer Tracking", "MEDIUM", "T1430"),

    # Call monitoring
    r"CallDetection|CallMonitor|CallRecord|CallListener": ("Call Monitoring / Recording", "HIGH", "T1433"),

    # C2 messaging (Roaming Mantis style)
    r"NMSGService|MRegService|MHoldService|CPZService": ("Covert C2 Messaging Service", "CRITICAL", "T1102"),

    # Telegram-based exfil
    r"SyncTG|TelegramSync|TGService|TGSync|TGUpload": ("Telegram C2 / Data Exfiltration", "HIGH", "T1102"),
}


SUSPICIOUS_STRINGS_SEMANTIC = {
    # C2 indicators
    r"(?i)(api\.telegram\.org|bot\d+:AA)": ("Telegram Bot C2", "HIGH", "T1102"),
    r"(?i)(discord\.com/api/webhooks)": ("Discord Webhook C2/Exfil", "HIGH", "T1102"),
    r"(?i)(ngrok\.io|serveo\.net|pagekite)": ("Tunnel Service C2", "HIGH", "T1572"),
    r"(?i)(\.onion)": ("Tor Hidden Service C2", "HIGH", "T1090"),
    r"(?i)(/api/bot|/sendmessage|/getupdat)": ("Bot API Call Pattern", "MEDIUM", "T1102"),

    # Credential/banking
    r"(?i)(inject|overlay|webinject)": ("Webinject/Overlay Terms", "HIGH", "T1417"),
    r"(?i)(keylog|keystroke|type_view_text)": ("Keylogging Strings", "HIGH", "T1417"),
    r"(?i)(ussd|mmsc|mms_url)": ("USSD/MMS Strings", "HIGH", "T1582"),

    # Ransomware
    r"(?i)(btc wallet|monero|xmr|your files are encrypted|pay.*ransom|send.*bitcoin.*decrypt)": ("Ransomware Strings", "CRITICAL", "T1486"),

    # Anti-analysis
    r"(?i)(isemulator|genymotion|bluestacks|nox|ldplayer|memu)": ("Emulator Detection", "MEDIUM", "T1633"),
    r"(?i)(root|superuser|magisk|busybox)": ("Root/Superuser Access", "HIGH", "T1626"),
    r"(?i)(frida|xposed|substrate|cydia)": ("Reverse Engineering Detection", "MEDIUM", "T1633"),
}


def compute_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_gibberish(name: str) -> bool:
    """Check if a name looks auto-generated/gibberish (consonant clusters, no vowels)."""
    # Strip package separators
    parts = re.split(r'[./]', name)
    short_consonant = [p for p in parts if re.match(r'^[bcdfghjklmnpqrstvwxyz]{3,}$', p, re.I)]
    return len(short_consonant) >= 2


class SemanticAnalyzer:
    """Semantic analysis of component names and strings."""

    def analyze_components(self, apk_result) -> list[SemanticFinding]:
        """Analyze all component names for semantic capability indicators."""
        findings = []

        all_components = (
            [(c.name, "service") for c in apk_result.services] +
            [(c.name, "activity") for c in apk_result.activities] +
            [(c.name, "receiver") for c in apk_result.receivers]
        )

        for full_name, comp_type in all_components:
            # Get the simple class name (last segment)
            simple = full_name.split(".")[-1]

            for pattern, (capability, severity, mitre) in COMPONENT_PATTERNS.items():
                if re.search(pattern, simple, re.IGNORECASE):
                    findings.append(SemanticFinding(
                        component=comp_type,
                        name=full_name,
                        capability=capability,
                        severity=severity,
                        mitre=mitre,
                        confidence=90,
                    ))
                    break  # one match per component

        return findings

    def analyze_strings_semantic(self, apk_result) -> list[SemanticFinding]:
        """Analyze interesting strings for semantic patterns."""
        findings = []
        seen = set()

        all_text = "\n".join(apk_result.all_strings[:3000])

        for pattern, (capability, severity, mitre) in SUSPICIOUS_STRINGS_SEMANTIC.items():
            matches = re.findall(pattern, all_text)
            if matches and capability not in seen:
                seen.add(capability)
                findings.append(SemanticFinding(
                    component="string",
                    name=str(matches[0])[:80],
                    capability=capability,
                    severity=severity,
                    mitre=mitre,
                    confidence=75,
                ))

        return findings

    def analyze_entropy(self, apk_result) -> list[dict]:
        """Find high-entropy strings that may be encrypted payloads or keys."""
        high_entropy = []
        for s in apk_result.all_strings:
            if len(s) < 16:
                continue
            ent = compute_entropy(s)
            if ent > 4.5:  # high entropy threshold
                high_entropy.append({"string": s[:80], "entropy": round(ent, 2), "length": len(s)})

        # Sort by entropy, return top 10
        return sorted(high_entropy, key=lambda x: -x["entropy"])[:10]

    def infer_malware_family(self, apk_result, component_findings: list[SemanticFinding]) -> dict:
        """
        Rule-based malware family inference from semantic analysis.
        Returns best guess with confidence.
        """
        capabilities = {f.capability for f in component_findings}
        cap_str = " ".join(capabilities).lower()

        families = []

        # Banking Trojan (Anubis/BankBot pattern)
        banking_score = 0
        if "overlay injection" in cap_str or "webinject" in cap_str: banking_score += 3
        if "accessibility" in cap_str: banking_score += 2
        if "sms" in cap_str: banking_score += 2
        if "ussd" in cap_str: banking_score += 3
        if "vnc" in cap_str or "remote control" in cap_str: banking_score += 2
        if "c2 command" in cap_str or "rat" in cap_str.lower(): banking_score += 3
        if banking_score >= 5:  # lowered threshold; accessibility+C2 = 5 is strong signal
            families.append(("Banking Trojan / RAT", banking_score * 10, "Anubis/BankBot lineage"))

        # Stalkerware
        spy_score = 0
        if "audio recording" in cap_str: spy_score += 3
        if "location tracking" in cap_str: spy_score += 2
        if "camera" in cap_str: spy_score += 2
        if "icon" in cap_str and "hid" in cap_str: spy_score += 3
        if "file enumeration" in cap_str: spy_score += 1
        if "call monitoring" in cap_str: spy_score += 3
        if "telegram c2" in cap_str: spy_score += 3
        if "notification interception" in cap_str: spy_score += 2
        if spy_score >= 5:
            families.append(("Stalkerware / Spyware", spy_score * 10, "Covert surveillance app"))

        # Ransomware
        ransom_score = 0
        if "screen locker" in cap_str: ransom_score += 4
        if "ransomware strings" in cap_str: ransom_score += 4
        if "device administrator" in cap_str: ransom_score += 2
        if ransom_score >= 4:
            families.append(("Ransomware / Screen Locker", ransom_score * 10, "Extortion malware"))

        # RAT
        rat_score = 0
        if "remote access trojan" in cap_str: rat_score += 5
        if "socks proxy" in cap_str: rat_score += 3
        if "screen capture" in cap_str: rat_score += 2
        if "c2 command" in cap_str: rat_score += 3
        if "covert c2 messaging" in cap_str: rat_score += 4
        if "metasploit" in cap_str: rat_score += 6
        if rat_score >= 4:
            families.append(("Remote Access Trojan (RAT)", rat_score * 10, "Full remote control"))

        # SMS Fraud / Spyware
        sms_score = 0
        if "covert sms sending" in cap_str: sms_score += 4
        if "sms/mms interception" in cap_str or "sms interception" in cap_str: sms_score += 3
        if "alarm-based persistence" in cap_str and "sms" in cap_str: sms_score += 2
        if sms_score >= 4:
            families.append(("SMS Fraud / Stealer", sms_score * 10, "SMS-based fraud or spyware"))

        # Ransomware (file encryption)
        if "file encryption" in cap_str:
            families.append(("Ransomware (File Encryptor)", 80, "Encrypts files on device storage"))

        # Dropper
        drop_score = 0
        pkg_name = apk_result.package_name or ""
        if is_gibberish(pkg_name): drop_score += 2
        if len(apk_result.dex_files) > 2: drop_score += 2
        any_dexloader = any("DexClassLoader" in str(api) for api in apk_result.api_calls)
        if any_dexloader: drop_score += 3
        if drop_score >= 4:
            families.append(("Dropper / Loader", drop_score * 10, "Downloads and executes payload"))

        if not families:
            return {"family": "Unknown", "confidence": 0, "note": "Insufficient indicators"}

        # Sort by score and take top match; combine if multiple high scores
        families.sort(key=lambda x: -x[1])
        primary = families[0]
        secondary = [f[0] for f in families[1:] if f[1] >= primary[1] * 0.6]

        label = primary[0]
        if secondary:
            label += " + " + " + ".join(secondary[:2])

        return {
            "family": label,
            "confidence": min(primary[1], 95),
            "note": primary[2],
            "all_candidates": [(f[0], f[1]) for f in families],
        }
