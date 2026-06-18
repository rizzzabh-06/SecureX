"""
APK Static Analyzer - powered by androguard
Extracts comprehensive features from Android APK files.
"""
import hashlib
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    sha256: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_self_signed: bool = False


@dataclass
class ComponentInfo:
    name: str
    exported: bool = False
    intent_filters: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)


@dataclass
class APKAnalysisResult:
    # File metadata
    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""
    sha1: str = ""

    # APK metadata
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    max_sdk: str = ""

    # Permissions
    declared_permissions: list[str] = field(default_factory=list)
    used_permissions: list[str] = field(default_factory=list)
    custom_permissions: list[str] = field(default_factory=list)

    # Components
    activities: list[ComponentInfo] = field(default_factory=list)
    services: list[ComponentInfo] = field(default_factory=list)
    receivers: list[ComponentInfo] = field(default_factory=list)
    providers: list[ComponentInfo] = field(default_factory=list)

    # Code analysis
    classes: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    suspicious_api_calls: list[dict] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)

    # Network IOCs
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    # Strings
    interesting_strings: list[dict] = field(default_factory=list)
    all_strings: list[str] = field(default_factory=list)

    # Certificate
    certificates: list[CertInfo] = field(default_factory=list)

    # Files in APK
    embedded_files: list[dict] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)

    # Obfuscation indicators
    obfuscation_score: int = 0
    obfuscation_indicators: list[str] = field(default_factory=list)

    # Errors
    errors: list[str] = field(default_factory=list)


SUSPICIOUS_API_CATEGORIES = {
    "Dynamic Code Loading": [
        "Ldalvik/system/DexClassLoader",
        "Ldalvik/system/InMemoryDexClassLoader",
        "Ldalvik/system/PathClassLoader",
        "Ljava/lang/ClassLoader",
    ],
    "Reflection": [
        "Ljava/lang/reflect/Method",
        "Ljava/lang/reflect/Field",
        "Ljava/lang/Class;->forName",
    ],
    "Native Execution": [
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder",
    ],
    "SMS Operations": [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
    ],
    "Audio Recording": [
        "Landroid/media/MediaRecorder",
        "Landroid/media/AudioRecord",
    ],
    "Location Tracking": [
        "Landroid/location/LocationManager;->requestLocationUpdates",
        "Landroid/location/LocationManager;->getLastKnownLocation",
    ],
    "Camera Access": [
        "Landroid/hardware/Camera",
        "Landroid/hardware/camera2/CameraManager",
    ],
    "Accessibility Service": [
        "Landroid/accessibilityservice/AccessibilityService",
        "Landroid/view/accessibility/AccessibilityNodeInfo",
    ],
    "Device Admin": [
        "Landroid/app/admin/DevicePolicyManager",
        "Landroid/app/admin/DeviceAdminReceiver",
    ],
    "Account Credentials": [
        "Landroid/accounts/AccountManager;->getAuthToken",
        "Landroid/accounts/AccountManager;->getPassword",
    ],
    "Notification Interception": [
        "Landroid/service/notification/NotificationListenerService",
    ],
    "Window Overlay": [
        "Landroid/view/WindowManager;->addView",
    ],
    "Cryptography": [
        "Ljavax/crypto/Cipher",
        "Ljavax/crypto/spec/SecretKeySpec",
    ],
    "Network Communication": [
        "Ljava/net/URL;->openConnection",
        "Lokhttp3/OkHttpClient",
        "Ljava/net/Socket",
    ],
    "Package Installation": [
        "Landroid/content/pm/PackageInstaller",
        "Landroid/content/pm/PackageManager;->installPackage",
    ],
}


class APKAnalyzer:
    """Main APK static analysis engine."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.result = APKAnalysisResult(file_path=apk_path)

    def analyze(self) -> APKAnalysisResult:
        """Run full static analysis on the APK."""
        logger.info(f"Starting analysis of: {self.apk_path}")

        self._compute_hashes()
        self._get_file_info()

        if not ANDROGUARD_AVAILABLE:
            self.result.errors.append(
                "androguard not available - limited analysis mode"
            )
            self._fallback_analysis()
            return self.result

        try:
            self._androguard_analysis()
        except Exception as e:
            logger.error(f"androguard analysis failed: {e}")
            self.result.errors.append(f"androguard error: {str(e)}")
            self._fallback_analysis()

        self._detect_obfuscation()
        return self.result

    def _compute_hashes(self):
        """Compute file hashes."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(self.apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            self.result.md5 = md5.hexdigest()
            self.result.sha1 = sha1.hexdigest()
            self.result.sha256 = sha256.hexdigest()
        except Exception as e:
            self.result.errors.append(f"hash computation error: {e}")

    def _get_file_info(self):
        """Get basic file info."""
        try:
            self.result.file_size = os.path.getsize(self.apk_path)
        except Exception:
            pass

    def _androguard_analysis(self):
        """Full analysis using androguard."""
        apk, dexes, analysis = AnalyzeAPK(self.apk_path)

        # APK metadata
        self.result.package_name = apk.get_package() or ""
        self.result.app_name = apk.get_app_name() or ""
        self.result.version_name = apk.get_androidversion_name() or ""
        self.result.version_code = str(apk.get_androidversion_code() or "")
        self.result.min_sdk = str(apk.get_min_sdk_version() or "")
        self.result.target_sdk = str(apk.get_target_sdk_version() or "")
        self.result.max_sdk = str(apk.get_max_sdk_version() or "")

        # Permissions
        self.result.declared_permissions = list(apk.get_declared_permissions() or [])
        self.result.used_permissions = list(apk.get_permissions() or [])

        # Custom permissions (declared but not standard Android)
        standard_prefix = "android.permission."
        self.result.custom_permissions = [
            p for p in self.result.declared_permissions
            if not p.startswith(standard_prefix)
        ]

        # Components
        self._extract_components(apk)

        # Files in APK
        self._extract_embedded_files(apk)

        # Certificate
        self._extract_certificates(apk)

        # DEX/code analysis
        self._analyze_dex(apk, dexes, analysis)

        # String extraction
        self._extract_strings_from_analysis(analysis)

    def _extract_components(self, apk):
        """Extract Android components from manifest."""
        # Activities
        for act in (apk.get_activities() or []):
            comp = ComponentInfo(name=act)
            try:
                comp.exported = apk.get_activity(act).get("exported") == "true"
            except Exception:
                pass
            try:
                filters = apk.get_intent_filters("activity", act)
                comp.intent_filters = [str(f) for f in (filters or [])]
            except Exception:
                pass
            self.result.activities.append(comp)

        # Services
        for svc in (apk.get_services() or []):
            comp = ComponentInfo(name=svc)
            try:
                comp.exported = apk.get_service(svc).get("exported") == "true"
            except Exception:
                pass
            self.result.services.append(comp)

        # Receivers
        for rcv in (apk.get_receivers() or []):
            comp = ComponentInfo(name=rcv)
            try:
                comp.exported = apk.get_receiver(rcv).get("exported") == "true"
            except Exception:
                pass
            try:
                filters = apk.get_intent_filters("receiver", rcv)
                comp.intent_filters = [str(f) for f in (filters or [])]
            except Exception:
                pass
            self.result.receivers.append(comp)

        # Providers
        for prov in (apk.get_providers() or []):
            comp = ComponentInfo(name=prov)
            self.result.providers.append(comp)

    def _extract_embedded_files(self, apk):
        """List files embedded in APK."""
        try:
            for fname in apk.get_files():
                info = {
                    "name": fname,
                    "size": 0,
                    "type": self._classify_file(fname),
                }
                try:
                    data = apk.get_file(fname)
                    info["size"] = len(data)
                    info["md5"] = hashlib.md5(data).hexdigest()

                    # Check for encrypted/compressed blobs
                    if fname.endswith((".so",)):
                        self.result.native_libs.append(fname)
                    elif fname.endswith(".dex"):
                        self.result.dex_files.append(fname)
                    elif fname.startswith("assets/"):
                        self.result.assets.append(fname)
                except Exception:
                    pass
                self.result.embedded_files.append(info)
        except Exception as e:
            self.result.errors.append(f"file extraction error: {e}")

    def _classify_file(self, fname: str) -> str:
        ext = Path(fname).suffix.lower()
        categories = {
            ".dex": "Dalvik Executable",
            ".so": "Native Library",
            ".jar": "Java Archive",
            ".apk": "Embedded APK",
            ".zip": "Archive",
            ".png": "Image",
            ".jpg": "Image",
            ".xml": "XML Resource",
            ".db": "Database",
            ".sqlite": "Database",
            ".json": "JSON Data",
            ".js": "JavaScript",
            ".html": "HTML",
            ".php": "PHP Script",
            ".sh": "Shell Script",
        }
        return categories.get(ext, "Unknown")

    def _extract_certificates(self, apk):
        """Extract signing certificate information."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes

            # Try v2/v3 signing first, then v1 JAR signing
            cert_sources = []
            try:
                v2 = apk.get_certificates_der_v2()
                if v2:
                    cert_sources.extend(v2)
            except Exception:
                pass
            if not cert_sources:
                try:
                    v1 = apk.get_certificates()
                    if v1:
                        cert_sources.extend(v1)
                except Exception:
                    pass

            for cert_raw in cert_sources:
                cert_info = CertInfo()
                try:
                    # cert_raw may be bytes or a cryptography Certificate object
                    if isinstance(cert_raw, (bytes, bytearray)):
                        cert = x509.load_der_x509_certificate(bytes(cert_raw))
                    elif hasattr(cert_raw, 'subject'):
                        cert = cert_raw  # already a Certificate object
                    else:
                        # androguard may return its own cert objects — get DER bytes
                        der = cert_raw.dump() if hasattr(cert_raw, 'dump') else bytes(cert_raw)
                        cert = x509.load_der_x509_certificate(der)

                    cert_info.subject = cert.subject.rfc4514_string()
                    cert_info.issuer = cert.issuer.rfc4514_string()
                    cert_info.serial = str(cert.serial_number)
                    cert_info.sha256 = cert.fingerprint(hashes.SHA256()).hex()
                    try:
                        cert_info.valid_from = str(cert.not_valid_before_utc)
                        cert_info.valid_to = str(cert.not_valid_after_utc)
                    except AttributeError:
                        cert_info.valid_from = str(cert.not_valid_before)
                        cert_info.valid_to = str(cert.not_valid_after)
                    cert_info.is_self_signed = cert.subject == cert.issuer
                except Exception:
                    try:
                        raw_bytes = bytes(cert_raw) if not isinstance(cert_raw, bytes) else cert_raw
                        cert_info.sha256 = hashlib.sha256(raw_bytes).hexdigest()
                    except Exception:
                        pass
                self.result.certificates.append(cert_info)
        except Exception as e:
            self.result.errors.append(f"cert extraction error: {e}")

    def _analyze_dex(self, apk, dexes, analysis):
        """Analyze DEX bytecode for suspicious patterns."""
        seen_classes = set()
        seen_apis = set()

        try:
            for cls in analysis.get_classes():
                name = cls.name
                seen_classes.add(name)

                for method in cls.get_methods():
                    for _, call, _ in method.get_xref_to():
                        api = f"{call.class_name}->{call.name}"
                        seen_apis.add(api)

                        # Check against suspicious API list
                        for category, patterns in SUSPICIOUS_API_CATEGORIES.items():
                            for pattern in patterns:
                                if pattern in api or pattern in call.class_name:
                                    entry = {
                                        "api": api,
                                        "category": category,
                                        "class": str(cls.name),
                                        "method": str(method.name),
                                    }
                                    if entry not in self.result.suspicious_api_calls:
                                        self.result.suspicious_api_calls.append(entry)

            self.result.classes = list(seen_classes)[:500]  # cap at 500
            self.result.api_calls = list(seen_apis)[:1000]

        except Exception as e:
            logger.warning(f"DEX analysis partial error: {e}")
            self.result.errors.append(f"DEX analysis: {e}")

    def _extract_strings_from_analysis(self, analysis):
        """Extract and classify strings from the app."""
        url_pattern = re.compile(
            r'https?://[^\s\'"<>]{4,200}', re.IGNORECASE
        )
        ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b'
        )
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|onion|'
            r'info|biz|cc|pw|me|su)\b'
        )

        seen_strings = set()
        try:
            for string_val in analysis.get_strings():
                s = str(string_val)
                if len(s) < 4 or len(s) > 1000:
                    continue
                if s in seen_strings:
                    continue
                seen_strings.add(s)

                # Extract IOCs
                for url in url_pattern.findall(s):
                    if url not in self.result.urls:
                        self.result.urls.append(url)

                for ip in ip_pattern.findall(s):
                    # Filter private ranges
                    if not self._is_private_ip(ip.split(":")[0]):
                        if ip not in self.result.ips:
                            self.result.ips.append(ip)

                for email in email_pattern.findall(s):
                    if email not in self.result.emails:
                        self.result.emails.append(email)

            self.result.all_strings = list(seen_strings)[:2000]

            # Find domain from URLs
            for url in self.result.urls:
                m = re.match(r'https?://([^/:?#]+)', url)
                if m:
                    domain = m.group(1)
                    if domain not in self.result.domains:
                        self.result.domains.append(domain)

        except Exception as e:
            logger.warning(f"String extraction error: {e}")
            self.result.errors.append(f"string extraction: {e}")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        private_ranges = [
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0.0.0.",
            "169.254.", "224.", "240.", "255.",
        ]
        return any(ip.startswith(r) for r in private_ranges)

    def _fallback_analysis(self):
        """Basic analysis without androguard (ZIP parsing)."""
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for info in zf.infolist():
                    file_entry = {
                        "name": info.filename,
                        "size": info.file_size,
                        "type": self._classify_file(info.filename),
                    }
                    self.result.embedded_files.append(file_entry)
                    if info.filename.endswith(".so"):
                        self.result.native_libs.append(info.filename)
                    elif info.filename.endswith(".dex"):
                        self.result.dex_files.append(info.filename)

                    # Try to extract strings from raw files
                    try:
                        data = zf.read(info.filename)
                        self._extract_strings_from_bytes(data)
                    except Exception:
                        pass
        except Exception as e:
            self.result.errors.append(f"ZIP fallback error: {e}")

    def _extract_strings_from_bytes(self, data: bytes):
        """Extract printable strings from raw bytes."""
        strings = re.findall(b'[\x20-\x7e]{6,200}', data)

        # Extract URLs and IPs once per buffer (not per string — avoids O(n²))
        url_pattern = re.compile(rb'https?://[^\s\'"<>]{4,200}')
        ip_pattern = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')

        for url_b in url_pattern.findall(data):
            url = url_b.decode("ascii", errors="ignore")
            if url not in self.result.urls:
                self.result.urls.append(url)

        for ip_b in ip_pattern.findall(data):
            ip = ip_b.decode("ascii", errors="ignore")
            if not self._is_private_ip(ip) and ip not in self.result.ips:
                self.result.ips.append(ip)

        for s_bytes in strings:
            try:
                s = s_bytes.decode("ascii", errors="ignore")
                self.result.all_strings.append(s)
            except Exception:
                pass

    def _detect_obfuscation(self):
        """Detect code obfuscation indicators."""
        indicators = []
        score = 0

        if not self.result.classes:
            return

        # Short class/method names (ProGuard/DexGuard)
        short_names = [c for c in self.result.classes if len(c.strip("L;").split("/")[-1]) <= 2]
        if len(short_names) > len(self.result.classes) * 0.4:
            indicators.append(f"High ratio of short class names ({len(short_names)}/{len(self.result.classes)}) - likely ProGuard/DexGuard")
            score += 3

        # Single letter packages
        single_letter_pkgs = [c for c in self.result.classes if re.match(r'^L[a-z]/[a-z];?$', c)]
        if single_letter_pkgs:
            indicators.append(f"Single-letter package names detected ({len(single_letter_pkgs)} classes)")
            score += 2

        # Dynamic class loading
        dex_loaders = [
            c for c in self.result.api_calls
            if "DexClassLoader" in c or "InMemoryDexClassLoader" in c
        ]
        if dex_loaders:
            indicators.append("Dynamic DEX class loading detected")
            score += 3

        # Reflection usage
        reflect_calls = [c for c in self.result.api_calls if "reflect" in c.lower()]
        if len(reflect_calls) > 5:
            indicators.append(f"Heavy reflection usage ({len(reflect_calls)} calls)")
            score += 2

        # Encrypted/encoded strings
        b64_strings = [
            s for s in self.result.all_strings
            if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', s)
        ]
        if b64_strings:
            indicators.append(f"Potential Base64 encoded payloads ({len(b64_strings)} strings)")
            score += 2

        # Multiple DEX files (multidex = common in packers)
        if len(self.result.dex_files) > 3:
            indicators.append(f"Multiple DEX files ({len(self.result.dex_files)}) - possible packer")
            score += 2

        # Known RAT/malware package name signatures
        pkg_lower = (self.result.package_name or "").lower()
        if "metasploit" in pkg_lower:
            indicators.append(f"Metasploit package name detected: '{self.result.package_name}'")
            score += 5
        if "meterpreter" in pkg_lower:
            indicators.append(f"Meterpreter package name detected")
            score += 5

        # fddo-style repeated obfuscation token (Anubis/BankBot builder pattern)
        fddo_classes = [c for c in self.result.classes if "fddo" in c.lower()]
        if len(fddo_classes) > 3:
            indicators.append(f"'fddo' obfuscation token detected ({len(fddo_classes)} classes) - Anubis/BankBot builder")
            score += 3

        # Gibberish package name (consonant clusters, no vowel pattern)
        import re as _re, math as _math
        pkg = self.result.package_name or ""
        parts = pkg.replace(".", " ").split()
        # Classic: pure consonant clusters
        gibberish = [p for p in parts if _re.match(r'^[bcdfghjklmnpqrstvwxyz]{4,}$', p, _re.I)]
        # Extended: very long (>14 char) purely lowercase alpha segments (auto-generated)
        long_random = [p for p in parts if len(p) > 14 and _re.match(r'^[a-z]+$', p)]
        if len(gibberish) >= 2 or len(long_random) >= 2:
            indicators.append(f"Gibberish/auto-generated package name '{pkg}'")
            score += 2

        # Randomly named services/activities (all-lowercase, short, non-meaningful)
        all_comp_names = (
            [s.name.split(".")[-1] for s in self.result.services] +
            [a.name.split(".")[-1] for a in self.result.activities]
        )
        random_comps = [n for n in all_comp_names if _re.match(r'^[a-z]{4,12}$', n)]
        if len(random_comps) >= 4:
            indicators.append(f"Random all-lowercase component names ({len(random_comps)} found) - obfuscated builder")
            score += 2

        self.result.obfuscation_score = min(score, 10)
        self.result.obfuscation_indicators = indicators
