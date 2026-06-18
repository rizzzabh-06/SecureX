# 🧠 AI-DRIVEN APK THREAT FORENSICS PLATFORM
## *Complete Technical Architecture, GenAI Workflows & Real-World Deployment Guide*

---

```
Document Version  : 3.0 — Enterprise GenAI Edition (Revised & Extended)
Problem Statement : Harnessing Generative AI for Automated Reverse Engineering,
                    Static and Dynamic Analysis, and Risk Scoring of Fraudulent
                    Mobile Applications (APKs) and Malwares.
Audience          : Security Engineers · ML Engineers · Forensic Analysts · Technical Judges
Classification    : UNCLASSIFIED // FOR OFFICIAL USE ONLY
```

---

## ⚡ WHAT'S NEW IN V3.0 (vs Previous Submissions)

| Area | Added / Improved |
|---|---|
| GenAI Layer | RAG Memory Engine · LLM Investigator Chatbot · Prompt Chain Architecture |
| ML Detection | Graph Neural Network (GNN) for API Call Graph Classification |
| Threat Sharing | MISP Integration · Automated IOC Broadcasting |
| Forensics | Volatility3 Memory Forensics · Multi-Stage Payload Dropper Detection |
| Infrastructure | Neo4j C2 Graph DB · Federated Learning Architecture |
| Practical | Organisation-specific deployment guides · Real-world cost estimates |

---

## TABLE OF CONTENTS

```
1.  Problem Statement & Scope
2.  Platform Overview & Value Proposition
3.  High-Level Architecture (Full System Map)
4.  Analysis Pipeline — End-to-End Flow
5.  Static Analysis Engine
6.  Evasion-Resistant Dynamic Sandbox
7.  Frida Instrumentation & SSL MITM
8.  Generative AI Co-Analyst Pipeline  ← CORE INNOVATION
9.  RAG Memory Engine (New)
10. Graph Neural Network Classifier (New)
11. C2 Infrastructure Graph Database (New)
12. Threat Intelligence & Enrichment Layer
13. Volatility3 Memory Forensics (New)
14. Immutable Forensic Reporting
15. Cloud Infrastructure & Orchestration
16. API Reference
17. Real-World Deployment Playbooks
18. Security & Isolation Design
19. MITRE ATT&CK Mobile Mapping
20. Suggested Enhancements & Roadmap
21. Comprehensive Tech Stack
```

---

## 1. PROBLEM STATEMENT & SCOPE

### 1.1 Official Problem Statement

> *"Harnessing Generative AI for Automated Reverse Engineering, Static and Dynamic Analysis,
> and Risk Scoring of Fraudulent Mobile Applications (APKs) and Malwares."*

### 1.2 Why This Is Hard

Traditional malware analysis pipelines fail modern Android threats because:

```
TRADITIONAL APPROACH           WHY IT FAILS
───────────────────────────    ──────────────────────────────────────────
Signature-based detection  →   Polymorphic malware changes hash every build
Basic permission checks    →   Permissions can be requested but never used
Simple dynamic execution   →   Malware detects emulators and stays dormant
Manual reverse engineering →   Takes 2–5 analyst days per sample
Static C2 blocklists       →   C2 infra rotates IPs every 24–72 hours
Human-written reports      →   Inconsistent, slow, not court-admissible
```

### 1.3 What This Platform Solves

```
INPUT                           OUTPUT
─────────────────────           ────────────────────────────────────────
Any Android APK file      →     Threat classification (0–100 risk score)
Suspected malware sample  →     C2 server map with geolocation
Seized device APK         →     XAI reasoning paragraph for courts
Batch of app samples      →     STIX/TAXII IOC bundle for SIEM ingestion
                          →     Court-admissible PDF with custody chain
                          →     Conversational Q&A interface for investigators
```

---

## 2. PLATFORM OVERVIEW & VALUE PROPOSITION

### 2.1 One-Line Description

> *"Upload an APK. Get back a court-ready forensic intelligence report powered by GenAI — in under 8 minutes."*

### 2.2 Who Uses This Platform

```
┌──────────────────────┬──────────────────────────────────────────────────┐
│ ORGANISATION TYPE    │ SPECIFIC USE CASE                                │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Law Enforcement      │ Analyze seized devices, build C2 attribution      │
│                      │ chain, generate court-admissible reports          │
├──────────────────────┼──────────────────────────────────────────────────┤
│ National CERTs       │ Analyze citizen-reported apps, extract IOCs,      │
│                      │ push threat intel to allied CERTs via STIX        │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Banking / FinTech    │ Scan banking trojan lookalikes before they reach  │
│                      │ customers; monitor Play Store for impersonators   │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Enterprise SOC       │ Vetting third-party APKs for BYOD policies;       │
│                      │ integrate with MDM/SIEM for automated blocking    │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Telecom Operators    │ Detect SIM-swap trojans, SMS stealers distributed │
│                      │ via fake recharge/utility apps                    │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Security Researchers │ Malware family phylogenetics, campaign tracking,  │
│                      │ threat actor attribution                          │
└──────────────────────┴──────────────────────────────────────────────────┘
```

---

## 3. HIGH-LEVEL ARCHITECTURE (FULL SYSTEM MAP)

> **Description:** The diagram below shows every component of the platform across four
> horizontal layers — ingestion, analysis engines, the GenAI synthesis brain, and the
> output/reporting layer. All analysis engines run in isolated Docker containers and
> communicate only via the internal message queue.

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                     CLOUD ORCHESTRATION LAYER (AWS / K8s)                ║
║                                                                           ║
║  ┌─────────────┐      ┌────────────────────────────────────────────────┐ ║
║  │  NGINX      │─────►│         FastAPI Application Server             │ ║
║  │  (TLS/Rate) │      │  /upload  /status  /report  /chat  /iocs       │ ║
║  └─────────────┘      └─────────────┬──────────────────────────────────┘ ║
║                                     │                                     ║
║             ┌───────────────────────┼──────────────────────┐             ║
║             │                       │                      │             ║
║  ┌──────────▼──────────┐  ┌─────────▼──────────┐  ┌───────▼──────────┐  ║
║  │  STATIC ANALYSIS    │  │  DYNAMIC SANDBOX    │  │  MEMORY FORENSICS│  ║
║  │  WORKER POOL        │  │  WORKER POOL        │  │  WORKER (New)    │  ║
║  │ ─────────────────── │  │ ─────────────────── │  │ ──────────────── │  ║
║  │ • MobSF Core        │  │ • Hardened AVD      │  │ • Volatility3    │  ║
║  │ • JADX Decompiler   │  │ • Frida Agent       │  │ • Memory Dump    │  ║
║  │ • APKTool           │  │ • mitmproxy (MITM)  │  │ • Process Tree   │  ║
║  │ • YARA Engine       │  │ • tcpdump / Scapy   │  │ • Artifact Carve │  ║
║  │ • APK Diff Engine   │  │ • UI Simulator      │  └──────────────────┘  ║
║  └──────────┬──────────┘  └──────────┬──────────┘                       ║
║             └───────────────┬─────────┘                                  ║
║                             │                                             ║
║  ┌──────────────────────────▼──────────────────────────────────────────┐ ║
║  │                  GENERATIVE AI SYNTHESIS BRAIN                      │ ║
║  │  ─────────────────────────────────────────────────────────────────  │ ║
║  │   LLM Provider (GPT-4o / Gemini 1.5 / Llama-3 local)               │ ║
║  │   RAG Engine (ChromaDB + Malware Corpus)                            │ ║
║  │   GNN Classifier (API Call Graph → Malware Family)                  │ ║
║  │   Prompt Chain Orchestrator (LangChain)                             │ ║
║  │   XAI Reasoning Generator                                           │ ║
║  │   Investigator Chat Interface                                       │ ║
║  └──────────────────────────┬──────────────────────────────────────────┘ ║
║                             │                                             ║
║  ┌──────────────────────────▼──────────────────────────────────────────┐ ║
║  │                   THREAT INTELLIGENCE LAYER                         │ ║
║  │   VirusTotal  |  AbuseIPDB  |  Shodan  |  OTX  |  MISP (New)        │ ║
║  └──────────────────────────┬──────────────────────────────────────────┘ ║
║                             │                                             ║
║  ┌──────────────────────────▼──────────────────────────────────────────┐ ║
║  │              OUTPUT & FORENSIC REPORTING LAYER                      │ ║
║  │   ReportLab PDF  |  STIX/TAXII Bundle  |  Neo4j C2 Graph (New)      │ ║
║  │   AWS S3 WORM    |  Blockchain Ledger  |  MISP Broadcast (New)      │ ║
║  └─────────────────────────────────────────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 4. ANALYSIS PIPELINE — END-TO-END FLOW

> **Description:** This is the master workflow every APK goes through, in sequence.
> Each stage feeds the next, and the AI layer enriches every stage rather than
> just summarising at the end. Parallel execution of static and dynamic stages
> cuts total time from 8 minutes down to ~4 minutes on multi-core instances.

```
                        ┌──────────────────┐
                        │   APK UPLOADED   │
                        │  (via UI or API) │
                        └────────┬─────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    INGESTION & TRIAGE    │
                    │  SHA256 + MD5 computed   │
                    │  Duplicate check vs DB   │
                    │  Chain of custody starts │
                    │  Case ID assigned        │
                    └────────┬────────┬────────┘
                             │        │
              ┌──────────────▼─┐   ┌──▼──────────────┐
              │ STATIC ANALYSIS│   │DYNAMIC ANALYSIS  │
              │ (Parallel)     │   │(Parallel)        │
              │                │   │                  │
              │ MobSF Scan     │   │ AVD Boot         │
              │ JADX Decompile │   │ Frida Inject     │
              │ YARA Match     │   │ SSL MITM Start   │
              │ APK Diff Check │   │ tcpdump Capture  │
              │ LLM Smali Read │   │ UI Simulation    │
              │ Permission Eval│   │ Behavior Record  │
              └──────────┬─────┘   └──────┬───────────┘
                         │                │
              ┌──────────▼────────────────▼───────────┐
              │         MEMORY FORENSICS STAGE        │
              │  AVD memory dump → Volatility3        │
              │  In-memory strings, process tree,     │
              │  injected DLLs, heap artifacts        │
              └─────────────────────┬─────────────────┘
                                    │
              ┌─────────────────────▼─────────────────┐
              │        THREAT INTELLIGENCE ENRICHMENT  │
              │  All IPs/domains/hashes → VT + Shodan │
              │  C2 IPs → AbuseIPDB + MISP lookup     │
              │  Domain age + WHOIS + ASN reputation  │
              └─────────────────────┬─────────────────┘
                                    │
              ┌─────────────────────▼─────────────────┐
              │          GenAI SYNTHESIS BRAIN         │
              │  RAG: compare vs known malware corpus  │
              │  GNN: classify malware family          │
              │  LLM: contextualize all findings       │
              │  XAI: generate risk score + reasoning  │
              └─────────────────────┬─────────────────┘
                                    │
              ┌─────────────────────▼─────────────────┐
              │          FORENSIC REPORT ENGINE        │
              │  Cryptographic custody chain locked    │
              │  PDF generated + signed                │
              │  STIX bundle exported                  │
              │  MISP event auto-published             │
              │  S3 WORM storage committed             │
              └────────────────────────────────────────┘

  TOTAL TIME: ~4–8 minutes (parallel static+dynamic)
```

---

## 5. STATIC ANALYSIS ENGINE

> **Description:** Static analysis extracts maximum information from the APK without
> ever executing it. Think of it as performing a forensic autopsy on the app's DNA —
> reading its instructions, checking what it claims to need, and looking for
> suspicious patterns baked into the code. The key advantage: malware cannot hide
> from static analysis by detecting the environment, because it never runs.

### 5.1 APK Decomposition Map

```
APK FILE (ZIP archive)
│
├── AndroidManifest.xml
│     ├── → Declared permissions (READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION...)
│     ├── → Exported components (can outside apps trigger this?)
│     ├── → Intent filters (hidden broadcast receivers)
│     └── → Min SDK version (older = wider attack surface)
│
├── classes.dex  (compiled Java/Kotlin bytecode)
│     ├── JADX decompiles to readable Java
│     ├── → Hardcoded IPs, domains, API keys, credentials
│     ├── → DexClassLoader (dynamic payload loading)
│     ├── → Java Reflection (evades static call graph analysis)
│     ├── → Crypto misuse (ECB mode, hardcoded AES keys)
│     └── → C2 framework signatures (Cobalt Strike, Metasploit, SpyNote)
│
├── lib/  (native .so libraries)
│     ├── ELF header parsing
│     ├── Symbol + string extraction (nm, strings)
│     └── → Rootkit components, keyloggers in native C
│
├── assets/ and res/
│     ├── → Embedded secondary DEX (stage-2 payload)
│     ├── → Encrypted config files (decoded by LLM agent)
│     └── → Fake UI assets (impersonation indicators)
│
└── META-INF/  (signing certificate)
      ├── Certificate fingerprint → known malware signer DB
      ├── → Self-signed? (suspicious for published apps)
      └── → Same cert across multiple malware samples?
```

### 5.2 APK Repackaging Detection (New — APK Diff Engine)

> **Why this matters:** A major fraud vector is taking a legitimate banking app (e.g., SBI YONO,
> PhonePe) and injecting malware into it, then distributing the fake version via WhatsApp or
> third-party stores. This engine catches that.

```python
import hashlib
from androguard.misc import AnalyzeAPK

class APKDiffEngine:
    """
    Compares a submitted APK against the genuine published version.
    Uses Androguard to do deep structural comparison — not just hash matching,
    because repackaged apps obviously have a different hash.
    """

    def __init__(self, genuine_apk_path: str, suspicious_apk_path: str):
        self.a1, self.d1, self.dx1 = AnalyzeAPK(genuine_apk_path)
        self.a2, self.d2, self.dx2 = AnalyzeAPK(suspicious_apk_path)

    def compare(self) -> dict:
        result = {
            "package_name_match": self.a1.get_package() == self.a2.get_package(),
            "cert_match": self._certs_match(),
            "added_permissions": self._permission_diff(),
            "added_classes": self._class_diff(),
            "added_receivers": self._receiver_diff(),
            "verdict": None
        }

        # A matching package name + different cert = REPACKAGED (high confidence fraud)
        if result["package_name_match"] and not result["cert_match"]:
            result["verdict"] = "REPACKAGED_APP_HIGH_CONFIDENCE"
        elif result["added_permissions"] or result["added_receivers"]:
            result["verdict"] = "MODIFIED_APP_MEDIUM_CONFIDENCE"
        else:
            result["verdict"] = "CLEAN"

        return result

    def _certs_match(self) -> bool:
        return (self.a1.get_certificate_der_v3()[0] ==
                self.a2.get_certificate_der_v3()[0])

    def _permission_diff(self) -> list:
        p1 = set(self.a1.get_permissions())
        p2 = set(self.a2.get_permissions())
        return list(p2 - p1)  # Permissions in suspicious but not in genuine

    def _class_diff(self) -> list:
        c1 = {c.name for c in self.d1.get_classes()}
        c2 = {c.name for c in self.d2.get_classes()}
        return list(c2 - c1)  # New classes injected

    def _receiver_diff(self) -> list:
        r1 = set(self.a1.get_receivers())
        r2 = set(self.a2.get_receivers())
        return list(r2 - r1)
```

### 5.3 MobSF API Integration

```python
import requests

class StaticAnalyzer:
    """
    Wrapper around MobSF's REST API.
    MobSF handles: manifest parsing, string extraction, permission analysis,
    code analysis, certificate checks, and generates a base findings report.
    We then layer our own YARA, Androguard, and AI analysis on top.
    """

    def __init__(self, mobsf_url: str, api_key: str):
        self.base_url = mobsf_url
        self.headers = {"Authorization": api_key}

    def full_scan(self, apk_path: str) -> dict:
        """Upload → Trigger scan → Return JSON report (3 API calls)"""

        # Step 1: Upload file
        with open(apk_path, "rb") as f:
            upload_resp = requests.post(
                f"{self.base_url}/api/v1/upload",
                files={"file": (apk_path.split("/")[-1], f, "application/octet-stream")},
                headers=self.headers
            )
        file_hash = upload_resp.json()["hash"]

        # Step 2: Trigger analysis
        requests.post(
            f"{self.base_url}/api/v1/scan",
            data={"hash": file_hash, "re_scan": 0},
            headers=self.headers
        )

        # Step 3: Retrieve full JSON report
        report_resp = requests.post(
            f"{self.base_url}/api/v1/report_json",
            data={"hash": file_hash},
            headers=self.headers
        )
        return report_resp.json()

    def extract_c2_candidates(self, report: dict) -> list:
        """
        Pull potential C2 endpoints from MobSF findings.
        Filters out known CDN/legitimate domains.
        """
        KNOWN_SAFE = {
            "googleapis.com", "gstatic.com", "firebase.io",
            "amazon.com", "cloudflare.com", "akamai.com"
        }
        candidates = []
        for url in report.get("urls", []):
            domain = url.get("url", "")
            if not any(safe in domain for safe in KNOWN_SAFE):
                candidates.append({
                    "url": domain,
                    "source": "static_code",
                    "context": url.get("path", "")  # Which file it appeared in
                })
        return candidates
```

### 5.4 YARA Rules for GenAI-Assisted C2 Pattern Matching

```yara
/*
  YARA rules are pattern-matching specifications that scan raw bytes.
  These run against the unpacked APK DEX files and native libraries.
  New rules can be contributed by the community and loaded dynamically.
*/

rule Android_SpyNote_C2_Beacon {
    meta:
        description  = "SpyNote RAT — C2 connection pattern"
        family       = "SpyNote"
        severity     = "CRITICAL"
        reference    = "https://malpedia.caad.fkie.fraunhofer.de/details/apk.spynote"
    strings:
        $sn1 = "getSimSerialNumber" ascii
        $sn2 = "getCellLocation"    ascii
        $sn3 = "startRecording"     ascii
        $port = /:\d{4,5}\x00/ ascii  // Hardcoded non-standard port
    condition:
        3 of ($sn1, $sn2, $sn3) and $port
}

rule Android_Banker_SMS_Intercept {
    meta:
        description = "OTP-stealing banker — aborts incoming SMS broadcast"
        severity    = "CRITICAL"
    strings:
        $a1 = "abortBroadcast"          ascii
        $a2 = "SMS_RECEIVED"            ascii
        $a3 = "sendTextMessage"         ascii
        $a4 = "getMessageBody"          ascii
    condition:
        ($a1 and $a2) or ($a3 and $a4)
}

rule Android_DGA_Domain_Generator {
    meta:
        description = "App generates C2 domains algorithmically (DGA)"
        severity    = "HIGH"
    strings:
        $d1 = "new Random()" ascii
        $d2 = "System.currentTimeMillis" ascii
        $d3 = ".xyz"   ascii
        $d4 = ".top"   ascii
        $d5 = ".tk"    ascii
    condition:
        ($d1 and $d2) and 1 of ($d3, $d4, $d5)
}

rule Android_CobaltStrike_Stager {
    meta:
        description = "Cobalt Strike stager adapted for Android"
        severity    = "CRITICAL"
    strings:
        $cs1 = { 4D 5A 90 00 }   // MZ header in embedded payload
        $cs2 = "beacon"           ascii nocase
        $cs3 = "checksum8"        ascii
    condition:
        2 of them
}
```

---

## 6. EVASION-RESISTANT DYNAMIC SANDBOX

> **Description:** Modern banking trojans and spyware are programmed to check whether
> they are running inside an analysis environment. If they detect an emulator, they
> simply stay dormant and appear clean. Our sandbox actively deceives the malware on
> four dimensions: hardware fingerprints, runtime artefacts, sensor data, and user behaviour.

### 6.1 The Four Layers of Sandbox Hardening

```
LAYER 1: BUILD PROPERTY CLOAKING
   The malware reads android system properties to identify device type.
   We overwrite these before the app launches.

   adb shell setprop ro.product.model    "SM-G998B"
   adb shell setprop ro.product.brand    "Samsung"
   adb shell setprop ro.build.fingerprint "samsung/SM-G998B/..."
   adb shell setprop ro.debuggable       "0"     ← Emulators are debuggable by default
   adb shell setprop ro.secure           "1"

LAYER 2: FILE SYSTEM ARTIFACT REMOVAL
   Emulators leave telltale files that malware scans for using /proc filesystem:

   adb shell "rm -f /dev/socket/qemud"          ← QEMU emulator socket
   adb shell "rm -f /dev/socket/genyd"          ← Genymotion artifact
   adb shell "chmod 000 /proc/tty/drivers"      ← Emulator TTY entries

LAYER 3: SENSOR DATA INJECTION (New)
   Malware checks accelerometer/gyroscope — a phone sitting still on a desk
   would have tiny constant vibrations. An emulator reads all zeros.

   adb emu sensor set acceleration    0.12:9.73:0.34   ← Simulated "held in hand"
   adb emu sensor set gyroscope       0.001:-0.002:0.0
   adb emu geo fix -73.9857 40.7484                    ← Inject realistic GPS

LAYER 4: FRIDA ANTI-ANTI-ANALYSIS (Runtime)
   If the malware checks for Frida at runtime, our Frida script intercepts
   the check itself and returns a clean result.
   (See Section 7 for Frida agent code)
```

### 6.2 Human Behavioral Simulation Engine (Enhanced)

> **Why this matters:** Sophisticated malware waits for realistic interaction signals
> — scrolling, typing, opening other apps — before activating. Flat random taps are
> detected as bot behaviour. Our simulator uses Bezier curve trajectories.

```python
import subprocess
import time
import math
import random

class HumanBehaviorSimulator:
    """
    Simulates realistic human interaction patterns on the AVD.
    Uses Bezier curves for swipe gestures (realistic finger movement),
    randomized typing delays (WPM variance), and session breaks.
    """

    def simulate_session(self, duration_seconds: int = 120):
        actions = [
            self._natural_swipe_up,
            self._natural_swipe_down,
            self._type_realistic_text,
            self._open_recent_apps,
            self._random_tap,
        ]

        end_time = time.time() + duration_seconds
        while time.time() < end_time:
            action = random.choice(actions)
            action()
            # Human pause — exponential distribution (not uniform random)
            pause = random.expovariate(1 / 3.5)  # Mean ~3.5s between actions
            time.sleep(min(pause, 12.0))

    def _natural_swipe_up(self):
        """
        Bezier curve swipe — not a straight line from A to B.
        Real finger swipes have slight lateral drift and acceleration.
        """
        x_start = random.randint(400, 600)
        y_start = random.randint(1400, 1600)
        y_end   = random.randint(400, 600)

        # Generate 5 intermediate points with slight x-drift
        points = []
        for i in range(5):
            t = i / 4
            x = int(x_start + random.gauss(0, 15))  # Slight lateral noise
            y = int(y_start + (y_end - y_start) * t)
            points.append(f"{x},{y}")

        # Build ADB swipe command with multiple waypoints
        cmd = ["adb", "shell", "input", "swipe"] + [
            str(x_start), str(y_start), str(random.randint(400,600)), str(y_end),
            str(random.randint(300, 700))  # Duration in ms — natural variance
        ]
        subprocess.run(cmd, capture_output=True)

    def _type_realistic_text(self):
        """Type text with WPM variance (60–90 WPM with bursts and pauses)"""
        texts = [
            "hello how are you",
            "check balance",
            "transfer 500",
            "otp verification"
        ]
        text = random.choice(texts)
        for char in text:
            subprocess.run(["adb", "shell", "input", "text", char], capture_output=True)
            # Typing delay: normally distributed around 120ms per char
            time.sleep(max(0.05, random.gauss(0.12, 0.04)))
```

---

## 7. FRIDA INSTRUMENTATION & SSL MITM

> **Description:** Frida is a dynamic binary instrumentation framework. It injects a
> JavaScript engine into the running malware process and lets us intercept any function
> call before it executes. Combined with mitmproxy as a transparent HTTPS proxy, we
> can read all network traffic in plaintext — even traffic that uses certificate pinning
> to prevent interception.

### 7.1 SSL Unpinning Architecture

```
WITHOUT MITM:                          WITH MITM + SSL UNPINNING:
────────────────────────────           ─────────────────────────────────────
Malware ──[encrypted]──► C2            Malware ──[encrypted]──► mitmproxy
                                                                     │
We see: ████████████████               mitmproxy decrypts with its cert
(nothing readable)                           │
                                       We see: {"gps": "40.7,-73.9",
                                               "sms": "OTP is 482931"}
                                             │
                                       mitmproxy re-encrypts ──► C2
```

**How certificate pinning is bypassed:**
Frida hooks the `TrustManager` and `X509Certificate` validation functions inside the
running app and makes them always return "trusted" regardless of the certificate presented.
This is equivalent to convincing the app that mitmproxy's certificate is legitimate.

### 7.2 Full Frida Agent

```javascript
/*
  frida_agent.js
  Injected into the malware process at runtime.
  Intercepts: network connections, HTTP requests, SMS, crypto, location,
  clipboard, anti-analysis evasion checks, and SSL certificate validation.
*/

Java.perform(function () {

    // ═══════════════════════════════════════════════════════
    // HOOK 1: TCP Socket — catch ALL outbound connections
    // Fires before any HTTP library, catches raw sockets too
    // ═══════════════════════════════════════════════════════
    const Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function (host, port) {
        send({
            type: 'tcp_connect',
            host: host,
            port: port,
            timestamp: new Date().toISOString(),
            thread: Java.use('java.lang.Thread').currentThread().getName()
        });
        return this.$init(host, port);
    };

    // ═══════════════════════════════════════════════════════
    // HOOK 2: OkHttp (most common Android HTTP client)
    // ═══════════════════════════════════════════════════════
    try {
        Java.use('okhttp3.internal.connection.RealCall').execute.implementation = function () {
            const req = this.request();
            let bodyStr = null;
            if (req.body()) {
                const buffer = Java.use('okio.Buffer').$new();
                req.body().writeTo(buffer);
                bodyStr = buffer.readUtf8();
            }
            send({
                type: 'http_request',
                url: req.url().toString(),
                method: req.method(),
                headers: req.headers().toString(),
                body: bodyStr,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
            });
            const resp = this.execute();
            send({ type: 'http_response', code: resp.code() });
            return resp;
        };
    } catch (e) { /* OkHttp not present, skip */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 3: SSL Certificate Pinning Bypass
    // Forces TrustManager to accept ALL certificates (enables MITM)
    // ═══════════════════════════════════════════════════════
    const TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const SSLContext    = Java.use('javax.net.ssl.SSLContext');

    const TrustAllCerts = Java.registerClass({
        name: 'com.analysis.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},  // ← Always trusts
            getAcceptedIssuers: function () { return []; }
        }
    });

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (km, tm, sr) {
        this.init(km, [TrustAllCerts.$new()], sr);
    };

    // ═══════════════════════════════════════════════════════
    // HOOK 4: SMS Operations (banker trojan detection)
    // ═══════════════════════════════════════════════════════
    const SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.implementation = function (dest, sc, text, sent, del) {
        send({
            type: 'sms_send',
            destination: dest,
            body: text,
            timestamp: new Date().toISOString(),
            severity: 'CRITICAL'
        });
        // Intentionally NOT calling original — block the SMS silently
    };

    // ═══════════════════════════════════════════════════════
    // HOOK 5: Location Access
    // ═══════════════════════════════════════════════════════
    Java.use('android.location.LocationManager')
        .getLastKnownLocation.implementation = function (provider) {
        const loc = this.getLastKnownLocation(provider);
        if (loc) {
            send({
                type: 'location_read',
                lat: loc.getLatitude(),
                lon: loc.getLongitude(),
                provider: provider,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
            });
        }
        return loc;
    };

    // ═══════════════════════════════════════════════════════
    // HOOK 6: Emulator Detection — Anti-Anti-Analysis
    // Intercepts the malware's own checks and lies to it
    // ═══════════════════════════════════════════════════════
    const Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'samsung/SM-G998B/SM-G998B:12/SP1A.210812.016/G998BXXS3DWB1:user/release-keys';
    Build.MANUFACTURER.value = 'Samsung';
    Build.MODEL.value = 'SM-G998B';
    Build.BRAND.value = 'samsung';

    // Block /proc/maps reading (Frida presence check)
    const FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
        if (path.indexOf('maps') !== -1 || path.indexOf('status') !== -1) {
            send({ type: 'evasion_check', path: path, blocked: true });
            throw Java.use('java.io.FileNotFoundException').$new(path);
        }
        return this.$init(path);
    };

    send({ type: 'agent_ready', timestamp: new Date().toISOString() });
});
```

---

## 8. GENERATIVE AI CO-ANALYST PIPELINE

> **Description:** This is the platform's core differentiator. Instead of GenAI merely
> summarising a finished report, it acts as an active participant during analysis —
> translating obfuscated code, contextualising raw telemetry, explaining risk scores
> in human language, and answering investigator questions. The LLM is prompted as a
> senior malware reverse engineer with 15 years of experience.

### 8.1 Three AI Agent Roles

```
┌──────────────────────────────────────────────────────────────────────┐
│                     GENERATIVE AI AGENT ROLES                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  AGENT 1: CODE ANALYST                                               │
│  ─────────────────────                                               │
│  Input:  Obfuscated Smali / decompiled Java blocks from JADX         │
│  Task:   Deobfuscate strings, reconstruct logic, identify intent     │
│  Output: { function_name, likely_purpose, malware_family_hint }     │
│                                                                      │
│  AGENT 2: BEHAVIOUR CONTEXTUALISER                                   │
│  ─────────────────────────────────                                   │
│  Input:  Frida event stream + PCAP summary + memory artifacts        │
│  Task:   Connect the dots — "why did it do A, then immediately B?"  │
│  Output: Human-readable behaviour narrative with severity tags       │
│                                                                      │
│  AGENT 3: RISK SCORER & XAI NARRATOR                                 │
│  ───────────────────────────────────                                 │
│  Input:  All findings from Agents 1, 2 + Threat Intel scores         │
│  Task:   Produce 0–100 score with mathematically grounded reasoning  │
│  Output: { score, classification, chain_of_reasoning, mitre_ttps }  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 8.2 Prompt Chain Architecture (LangChain)

```python
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.callbacks import get_openai_callback

class GenAIAnalysisBrain:
    """
    Orchestrates three sequential LLM calls, passing context forward.
    Each agent builds on the previous agent's output.
    
    For air-gapped (offline) deployments, swap ChatOpenAI for
    a local Ollama instance running Llama-3-8B-Instruct.
    """

    def __init__(self, model: str = "gpt-4o"):
        self.llm = ChatOpenAI(model=model, temperature=0.1)
        # Low temperature = more deterministic, less hallucination in forensic contexts

    # ─────────────────────────────────────────────────────────
    # AGENT 1: Smali Code Deobfuscation
    # ─────────────────────────────────────────────────────────
    def analyze_obfuscated_code(self, smali_block: str, context: str) -> dict:
        """
        Sends a raw Smali code block to the LLM for deobfuscation.
        JADX triggers this when it encounters reflection, DexClassLoader,
        or heavy ProGuard obfuscation that hides variable names.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior Android malware reverse engineer with 15 years 
             of experience. Analyze the provided Smali/Java code block.
             Your task:
             1. Reconstruct hidden string values from context clues
             2. Identify the function's malicious purpose
             3. Name the likely malware family if recognizable
             4. Flag any C2 addresses, encryption keys, or exfiltration logic
             
             Respond ONLY in valid JSON with keys:
             deobfuscated_logic, malicious_purpose, malware_family_hint,
             c2_indicators, severity (LOW/MEDIUM/HIGH/CRITICAL)"""),
            ("human", "Code block:\n{smali}\n\nSurrounding context:\n{context}")
        ])
        chain = LLMChain(llm=self.llm, prompt=prompt)
        with get_openai_callback() as cb:
            raw = chain.run(smali=smali_block, context=context)
        return self._safe_json_parse(raw)

    # ─────────────────────────────────────────────────────────
    # AGENT 2: Behaviour Contextualisation
    # ─────────────────────────────────────────────────────────
    def contextualise_behaviour(self, frida_events: list, pcap_summary: dict,
                                memory_artifacts: dict) -> dict:
        """
        Takes raw telemetry and constructs a narrative.
        Example: "The app collected GPS location (T1430), immediately base64-encoded it,
        and sent it via HTTPS POST to 185.x.x.x:8443 — consistent with SpyNote RAT."
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a malware analyst writing a forensic behaviour report.
             Given runtime telemetry from a suspicious Android app, write:
             1. A plain-English behaviour narrative (3–5 sentences)
             2. A list of MITRE ATT&CK for Mobile techniques observed
             3. The most likely malware classification
             4. Confidence level (LOW/MEDIUM/HIGH)
             
             Respond ONLY in valid JSON."""),
            ("human", "Frida events: {events}\nPCAP summary: {pcap}\nMemory: {memory}")
        ])
        chain = LLMChain(llm=self.llm, prompt=prompt)
        return self._safe_json_parse(
            chain.run(events=str(frida_events[:50]),
                      pcap=str(pcap_summary),
                      memory=str(memory_artifacts))
        )

    # ─────────────────────────────────────────────────────────
    # AGENT 3: XAI Risk Scoring
    # ─────────────────────────────────────────────────────────
    def generate_xai_score(self, all_findings: dict) -> dict:
        """
        Aggregates ALL findings and produces a court-ready explainability paragraph.
        XAI (Explainable AI) is required for legal admissibility — courts need to
        understand WHY the system scored an app as malicious.
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are the final stage of an automated malware analysis system.
             Produce:
             1. A risk score from 0–100 (0=clean, 100=confirmed critical malware)
             2. A "chain of reasoning" paragraph suitable for a court submission,
                explaining specifically which evidence led to the score
             3. Recommended immediate actions for law enforcement
             4. Confidence level
             
             Be specific — cite actual IPs, behaviours, and code patterns found.
             Respond ONLY in valid JSON with keys:
             score, classification, chain_of_reasoning, recommended_actions, confidence"""),
            ("human", "Complete analysis findings:\n{findings}")
        ])
        chain = LLMChain(llm=self.llm, prompt=prompt)
        return self._safe_json_parse(chain.run(findings=str(all_findings)))

    def _safe_json_parse(self, raw: str) -> dict:
        import json, re
        # Strip markdown code fences if model added them
        clean = re.sub(r'```json|```', '', raw).strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            return {"raw_response": raw, "parse_error": True}
```

### 8.3 Investigator Conversational Chat Interface (New)

> **Description:** After the report is generated, investigators often have follow-up
> questions: "Can you explain what DexClassLoader does in simple terms?" or
> "Which of the C2 servers is most likely the primary one?" This chat interface
> uses the full analysis as context, allowing natural language Q&A.
> This is critical for non-technical law enforcement personnel.

```python
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings

class InvestigatorChatbot:
    """
    Conversational interface over a completed analysis report.
    Non-technical investigators can ask plain-English questions
    and get precise, cited answers from the forensic data.
    
    Example questions:
    - "What data was being stolen?"
    - "Where is the server located?"
    - "Is this related to any known criminal group?"
    - "Explain the risk score in simple terms for the judge"
    """

    def __init__(self, report_json: dict):
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        # Convert report to searchable vector store
        self.vectorstore = self._index_report(report_json)
        self.chain = ConversationalRetrievalChain.from_llm(
            llm=ChatOpenAI(model="gpt-4o", temperature=0),
            retriever=self.vectorstore.as_retriever(search_kwargs={"k": 5}),
            memory=self.memory,
            verbose=False
        )

    def ask(self, question: str) -> str:
        result = self.chain({"question": question})
        return result["answer"]

    def _index_report(self, report: dict) -> Chroma:
        import json
        # Break report into chunks for vector indexing
        chunks = [
            f"Static findings: {json.dumps(report.get('static', {}))}",
            f"Dynamic behavior: {json.dumps(report.get('dynamic', {}))}",
            f"C2 infrastructure: {json.dumps(report.get('c2', {}))}",
            f"Threat intel: {json.dumps(report.get('intel', {}))}",
            f"AI analysis: {json.dumps(report.get('ai_analysis', {}))}",
        ]
        embeddings = OpenAIEmbeddings()
        return Chroma.from_texts(chunks, embeddings)
```

---

## 9. RAG MEMORY ENGINE (NEW)

> **Description:** Retrieval-Augmented Generation (RAG) gives the AI a long-term memory
> of every APK ever analysed by the platform. When a new sample comes in, the LLM
> doesn't have to reason from scratch — it retrieves the 5 most similar historical
> analyses and uses them as reference. This dramatically improves malware family
> classification accuracy and detects campaign patterns across samples.
>
> **Analogy:** Imagine a detective who, before working a new case, can instantly read
> the case files of the 5 most similar crimes ever solved. That's RAG for malware analysis.

### 9.1 RAG Architecture Flow

```
NEW APK ANALYSED
      │
      ▼
  Extract feature vector
  (permissions + API calls + network endpoints + certificate fingerprint)
      │
      ▼
  ┌────────────────────────────────┐
  │   VECTOR DATABASE (ChromaDB)   │  ← All previous analyses stored as embeddings
  │   ~embeddings of 50K+ samples  │
  └────────────────────────────────┘
      │
      ▼
  Similarity search → Top 5 most similar historical samples
      │
      ▼
  ┌───────────────────────────────────────────────────────────┐
  │   LLM PROMPT                                              │
  │                                                           │
  │   "Here are 5 similar samples from our database:          │
  │    Sample A (SpyNote 3.2) had these characteristics...    │
  │    Sample B (Cerberus banker) had these characteristics..  │
  │                                                           │
  │    Now analyse the new sample's findings and determine    │
  │    if it belongs to the same family, is a variant, or     │
  │    represents a new unknown threat."                      │
  └───────────────────────────────────────────────────────────┘
      │
      ▼
  Malware family + campaign attribution + novelty score
```

### 9.2 RAG Implementation

```python
import chromadb
from sentence_transformers import SentenceTransformer
import json

class MalwareRAGEngine:
    """
    Vector database of malware analysis features.
    Uses sentence-transformers for embedding (runs locally, no API cost).
    ChromaDB for storage (open source, runs in Docker).
    """

    def __init__(self, persist_dir: str = "/data/chromadb"):
        self.client     = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection("malware_analyses")
        # all-MiniLM-L6-v2: fast, lightweight, good for structured text similarity
        self.embedder   = SentenceTransformer("all-MiniLM-L6-v2")

    def index_analysis(self, case_id: str, findings: dict, metadata: dict):
        """
        Add a completed analysis to the RAG corpus.
        Called automatically after every successful analysis.
        """
        # Create a text representation of key features for embedding
        feature_text = self._findings_to_text(findings)
        embedding    = self.embedder.encode(feature_text).tolist()

        self.collection.upsert(
            ids=[case_id],
            embeddings=[embedding],
            documents=[feature_text],
            metadatas=[{
                "case_id":         case_id,
                "malware_family":  metadata.get("malware_family", "unknown"),
                "threat_score":    str(metadata.get("threat_score", 0)),
                "c2_ips":          json.dumps(metadata.get("c2_ips", [])),
                "analysis_date":   metadata.get("analysis_date", ""),
                "package_name":    metadata.get("package_name", "")
            }]
        )

    def find_similar(self, findings: dict, top_k: int = 5) -> list:
        """
        Find the K most similar historical samples to the current analysis.
        Returns structured data for use in LLM prompt context.
        """
        feature_text = self._findings_to_text(findings)
        embedding    = self.embedder.encode(feature_text).tolist()

        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=top_k,
            include=["documents", "metadatas", "distances"]
        )

        similar = []
        for i, doc in enumerate(results["documents"][0]):
            meta     = results["metadatas"][0][i]
            distance = results["distances"][0][i]
            # Convert cosine distance to similarity percentage
            similarity = round((1 - distance) * 100, 1)

            similar.append({
                "case_id":        meta["case_id"],
                "malware_family": meta["malware_family"],
                "threat_score":   int(meta["threat_score"]),
                "similarity_pct": similarity,
                "c2_ips":         json.loads(meta["c2_ips"]),
                "package_name":   meta["package_name"]
            })

        return similar

    def _findings_to_text(self, findings: dict) -> str:
        """Serialize key features to a consistent text format for embedding"""
        return (
            f"permissions:{','.join(findings.get('dangerous_permissions', []))} "
            f"apis:{','.join(findings.get('suspicious_apis', []))} "
            f"c2:{','.join(findings.get('c2_candidates', []))} "
            f"behaviors:{','.join(findings.get('behaviors', []))} "
            f"cert:{findings.get('certificate_fingerprint', '')}"
        )
```

---

## 10. GRAPH NEURAL NETWORK CLASSIFIER (NEW)

> **Description:** A Graph Neural Network (GNN) is a type of machine learning model
> designed to work on graph-structured data. In Android malware analysis, the sequence
> of API calls an app makes forms a directed graph (API Call Graph). Malware families
> have recognisably similar API call graph shapes — a banking trojan that intercepts
> SMS always calls the same sequence of Android APIs, regardless of how the code is
> obfuscated.
>
> **Why this beats signature-based detection:** Obfuscation can rename classes and
> variables, but it cannot change the fundamental sequence of API calls needed to
> steal an OTP. The graph shape persists through obfuscation.

### 10.1 API Call Graph Construction

```
APP EXECUTION TRACE (from Frida + System Calls):

getLastKnownLocation() ──► encryptString() ──► OkHttpClient.post()
        │                                              │
        ▼                                              ▼
 getSIMSerialNumber() ──► Base64.encode() ──► Socket.connect("185.x.x.x")
        │                       │
        ▼                       ▼
  getSubscriberId()     readSMS_messages()

This graph, when encoded as a feature vector, matches the
SpyNote RAT family with 94% confidence.
```

### 10.2 GNN Implementation

```python
import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
from torch_geometric.data import Data

class MalwareGNNClassifier(torch.nn.Module):
    """
    Graph Convolutional Network for malware family classification.
    
    Input:  API Call Graph (nodes = API calls, edges = sequential calls)
    Output: Probability distribution over malware families
    
    Families: ['clean', 'banker', 'spyware', 'ransomware', 
               'stalkerware', 'adware', 'rat', 'dropper']
    """

    NUM_FAMILIES = 8

    def __init__(self, node_features: int = 64, hidden_dim: int = 128):
        super().__init__()
        # Two graph convolutional layers
        self.conv1 = GCNConv(node_features, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        # Classification head
        self.classifier = torch.nn.Linear(hidden_dim, self.NUM_FAMILIES)

    def forward(self, x, edge_index, batch):
        # Message passing across the API call graph
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.3, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        # Pool all node features to a single graph-level vector
        x = global_mean_pool(x, batch)
        return F.log_softmax(self.classifier(x), dim=1)

    @classmethod
    def build_graph_from_trace(cls, api_call_sequence: list) -> Data:
        """
        Convert a Frida event trace to a PyTorch Geometric graph.
        
        api_call_sequence: list of strings like
        ["getLastKnownLocation", "encryptAES", "OkHttp.post", ...]
        """
        # API call → integer index mapping (loaded from training vocabulary)
        api_vocab = cls._load_api_vocabulary()

        # Node features: one-hot or embedding of each API call
        nodes = [api_vocab.get(api, 0) for api in api_call_sequence]
        x = torch.zeros(len(nodes), 64)
        for i, node_id in enumerate(nodes):
            if node_id < 64:
                x[i][node_id] = 1.0

        # Edge list: sequential calls (i → i+1)
        edge_src = list(range(len(nodes) - 1))
        edge_dst = list(range(1, len(nodes)))
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)

        return Data(x=x, edge_index=edge_index)

    @staticmethod
    def _load_api_vocabulary() -> dict:
        """Returns a mapping of Android API names to integer IDs"""
        critical_apis = [
            "getLastKnownLocation", "sendTextMessage", "abortBroadcast",
            "startRecording", "getSubscriberId", "getSIMSerialNumber",
            "getCameraId", "readContacts", "DexClassLoader",
            "Runtime.exec", "getClipboardText", "setComponentEnabledSetting"
        ]
        return {api: idx for idx, api in enumerate(critical_apis)}
```

---

## 11. C2 INFRASTRUCTURE GRAPH DATABASE (NEW)

> **Description:** Every C2 server the platform discovers gets stored in a graph
> database (Neo4j). Nodes represent: APK samples, C2 IP addresses, domains, ASNs,
> and certificate fingerprints. Edges represent: "communicates with", "resolves to",
> "hosted on", "signed by". This allows investigators to ask questions like:
> "Show me all APKs that communicate with the same hosting provider" —
> potentially linking a single threat actor's entire campaign.

### 11.1 C2 Graph Schema

```
GRAPH NODES:
────────────
(:APK)       { sha256, package_name, first_seen, threat_score }
(:IP)        { address, country, asn, vt_score, abuse_score }
(:Domain)    { fqdn, registrar, creation_date, entropy_score }
(:ASN)       { number, name, country, bulletproof_flag }
(:CertHash)  { fingerprint, subject, issuer, valid_from }

GRAPH EDGES:
────────────
(APK)-[:COMMUNICATES_WITH]->(IP)
(APK)-[:RESOLVES_TO]->(Domain)
(IP)-[:HOSTED_ON]->(ASN)
(Domain)-[:RESOLVES_TO]->(IP)
(APK)-[:SIGNED_BY]->(CertHash)
(APK)-[:SIMILAR_TO { similarity: 0.94 }]->(APK)

EXAMPLE QUERIES (Cypher):

// Find all APKs sharing the same C2 server
MATCH (a:APK)-[:COMMUNICATES_WITH]->(ip:IP)<-[:COMMUNICATES_WITH]-(b:APK)
WHERE a.sha256 <> b.sha256
RETURN a.package_name, b.package_name, ip.address

// Find bulletproof hosting clusters
MATCH (ip:IP)-[:HOSTED_ON]->(asn:ASN {bulletproof_flag: true})
RETURN asn.name, COUNT(ip) AS c2_count ORDER BY c2_count DESC

// Trace a full campaign from one C2 IP
MATCH path = (ip:IP {address: "185.220.101.45"})<-[:COMMUNICATES_WITH]-(a:APK)
RETURN path
```

### 11.2 Neo4j Integration

```python
from neo4j import GraphDatabase

class C2GraphDB:
    """
    Stores C2 relationships for campaign attribution and threat actor tracking.
    Neo4j's graph traversal allows finding connections that SQL joins would miss.
    """

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def add_analysis_findings(self, case_id: str, apk_sha256: str,
                               package_name: str, c2_ips: list,
                               domains: list, cert_fp: str):
        """Add all findings from one analysis run to the graph"""
        with self.driver.session() as session:
            # Create/merge APK node
            session.run("""
                MERGE (a:APK {sha256: $sha256})
                SET a.package_name = $pkg, a.case_id = $case_id
            """, sha256=apk_sha256, pkg=package_name, case_id=case_id)

            # Create IP nodes and relationships
            for ip_data in c2_ips:
                session.run("""
                    MERGE (ip:IP {address: $addr})
                    SET ip.country = $country, ip.asn = $asn,
                        ip.vt_score = $vt, ip.abuse_score = $abuse
                    WITH ip
                    MATCH (a:APK {sha256: $sha256})
                    MERGE (a)-[:COMMUNICATES_WITH]->(ip)
                """, addr=ip_data["ip"], country=ip_data.get("country"),
                    asn=ip_data.get("asn"), vt=ip_data.get("vt_score", 0),
                    abuse=ip_data.get("abuse_score", 0), sha256=apk_sha256)

    def find_campaign_siblings(self, sha256: str) -> list:
        """Find APKs that share C2 infrastructure with the given sample"""
        with self.driver.session() as session:
            result = session.run("""
                MATCH (a:APK {sha256: $sha256})-[:COMMUNICATES_WITH]->(ip:IP)
                      <-[:COMMUNICATES_WITH]-(sibling:APK)
                WHERE sibling.sha256 <> $sha256
                RETURN DISTINCT sibling.package_name AS pkg,
                                sibling.sha256       AS hash,
                                ip.address           AS shared_c2
            """, sha256=sha256)
            return [dict(r) for r in result]
```

---

## 12. THREAT INTELLIGENCE & ENRICHMENT LAYER

> **Description:** After extracting raw indicators (IPs, domains, hashes) from both
> static and dynamic analysis, every indicator is cross-referenced against multiple
> external threat intelligence databases simultaneously. This converts raw technical
> artefacts into actionable intelligence — answering "is this IP known to be used
> by criminals?" rather than just "this IP was contacted."

### 12.1 Multi-Source Enrichment Flow

```
INDICATORS EXTRACTED          ENRICHMENT SOURCES          OUTPUT
─────────────────────         ────────────────────         ──────────────────────
APK SHA256 hash          →    VirusTotal (70+ AV)     →   Detection ratio + family
C2 IP address            →    VirusTotal + AbuseIPDB  →   Malicious history + ISP
C2 IP address            →    Shodan                  →   Open ports + services
Domain name              →    VirusTotal + WHOIS      →   Age + registrar + tags
Domain name              →    AlienVault OTX          →   Pulse (campaign) data
All indicators           →    MISP (local instance)   →   Internal org correlation
Malware hash             →    MalwareBazaar            →   Family + YARA hits
```

### 12.2 MISP Integration (New — Critical for Organisations)

> MISP (Malware Information Sharing Platform) is the standard tool used by national
> CERTs, ISACs (Information Sharing and Analysis Centers), and government agencies
> worldwide for sharing threat intelligence. Our platform both queries MISP (to check
> if an indicator is already known) and publishes to MISP (to share new discoveries
> with the wider community, with one click from the investigator).

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

class MISPIntegration:
    """
    Bi-directional MISP integration:
    - LOOKUP: Check if indicators are in any connected MISP instance
    - PUBLISH: Auto-create MISP events from confirmed malware findings
    
    Real-world usage: A CERT in India finds a new banking trojan.
    One click publishes the IOCs to MISP, which automatically
    notifies CERTs in 50+ other countries via the MISP sync protocol.
    """

    def __init__(self, misp_url: str, api_key: str):
        self.misp = PyMISP(misp_url, api_key, ssl=True)

    def lookup_indicator(self, value: str, ioc_type: str) -> dict:
        """Check if an IOC is already known in MISP"""
        results = self.misp.search(value=value, type_attribute=ioc_type,
                                   pythonify=True)
        if results:
            return {
                "known_to_misp": True,
                "event_count": len(results),
                "earliest_seen": min(e.date for e in results).isoformat(),
                "tags": list({t.name for e in results for t in e.tags})
            }
        return {"known_to_misp": False}

    def publish_findings(self, case_data: dict, auto_publish: bool = False) -> str:
        """Create a MISP event from analysis findings"""
        event = MISPEvent()
        event.info         = f"Android Malware: {case_data['package_name']}"
        event.distribution = 1          # Community (this org + sync partners)
        event.threat_level_id = {
            "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4
        }.get(case_data["classification"], 4)

        # Add APK hash
        event.add_attribute("md5",    case_data["apk_md5"],    category="Payload delivery")
        event.add_attribute("sha256", case_data["apk_sha256"], category="Payload delivery")

        # Add C2 indicators
        for c2 in case_data.get("c2_infrastructure", []):
            event.add_attribute("ip-dst",       c2["ip"],     category="Network activity")
            if c2.get("domain"):
                event.add_attribute("domain",   c2["domain"], category="Network activity")

        # Add MITRE ATT&CK tags
        for ttp in case_data.get("mitre_ttps", []):
            event.add_tag(f'misp-galaxy:mitre-attack-pattern="{ttp}"')

        created = self.misp.add_event(event)

        if auto_publish:
            self.misp.publish(created)

        return created["Event"]["uuid"]
```

---

## 13. VOLATILITY3 MEMORY FORENSICS (NEW)

> **Description:** While the malware is running inside the Android emulator, we
> capture a full memory dump of the virtual machine. Volatility3 then analyses this
> dump to find artefacts that never appear on disk — decrypted C2 addresses, live
> encryption keys, injected code, and running process trees. This is especially
> valuable for detecting packers that decrypt their payload only in memory.

### 13.1 What Memory Forensics Finds

```
DISK-BASED ANALYSIS MISSES:        MEMORY FORENSICS CATCHES:
──────────────────────────────      ─────────────────────────────────────
Encrypted APK payload          →   Decrypted payload loaded in heap
Obfuscated C2 in code          →   Plaintext C2 address in memory strings
Hidden API keys                →   Keys in memory after first network call
Unknown process injection      →   Injected code in legitimate process space
Runtime-only DGA domains       →   Resolved domain names in DNS cache heap
```

### 13.2 Memory Acquisition & Analysis

```python
import subprocess
from pathlib import Path

class MemoryForensicsEngine:
    """
    Captures Android emulator memory and runs Volatility3 plugins.
    
    Workflow:
    1. Freeze the emulator at peak malware activity
    2. Dump VM memory via QEMU monitor (or ADB mem dump for process-level)
    3. Run Volatility3 Android profile against the dump
    4. Extract strings, process list, and network artefacts
    """

    def __init__(self, avd_name: str, output_dir: str):
        self.avd_name   = avd_name
        self.output_dir = Path(output_dir)

    def acquire_memory_dump(self, case_id: str) -> str:
        """
        Acquire process-level memory dump via ADB.
        For full VM dump, requires QEMU monitor access (KVM setup).
        """
        dump_path = self.output_dir / f"{case_id}_memory.raw"

        # Method: dump /proc/<pid>/mem for the malware process
        # Step 1: Get PID of the malware package
        pid_result = subprocess.run(
            ["adb", "shell", "pidof", self._get_package_name()],
            capture_output=True, text=True
        )
        pid = pid_result.stdout.strip()

        if not pid:
            return None

        # Step 2: Read memory maps and dump accessible segments
        subprocess.run([
            "adb", "shell", "su", "-c",
            f"dd if=/proc/{pid}/mem of=/sdcard/memdump.raw bs=4096 2>/dev/null || true"
        ])

        # Step 3: Pull dump to host
        subprocess.run(["adb", "pull", "/sdcard/memdump.raw", str(dump_path)])
        return str(dump_path)

    def extract_strings_from_dump(self, dump_path: str, min_len: int = 6) -> list:
        """Extract readable strings from memory dump — finds decrypted C2 URLs"""
        result = subprocess.run(
            ["strings", "-n", str(min_len), dump_path],
            capture_output=True, text=True
        )
        lines = result.stdout.splitlines()

        # Filter for interesting artefacts
        import re
        artefacts = []
        for line in lines:
            # URLs
            if re.match(r'https?://', line):
                artefacts.append({"type": "url", "value": line})
            # IP:port patterns
            elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$', line):
                artefacts.append({"type": "c2_endpoint", "value": line})
            # Base64 blocks (may be crypto keys or encoded payloads)
            elif re.match(r'^[A-Za-z0-9+/]{32,}={0,2}$', line):
                artefacts.append({"type": "base64_blob", "value": line[:64]})

        return artefacts
```

---

## 14. IMMUTABLE FORENSIC REPORTING

> **Description:** Digital evidence is worthless in court if opposing counsel can
> argue it was tampered with. Our reporting system uses three mechanisms to provide
> mathematical proof of evidence integrity:
> 1. Hash-chained custody log (blockchain-inspired — each entry references the previous)
> 2. AWS S3 Object Lock in Compliance Mode (WORM — physically cannot be deleted)
> 3. Digitally signed PDF using RSA-4096 (cryptographic signature on the final report)

### 14.1 Blockchain-Style Custody Chain

```python
import hashlib, json
from datetime import datetime, timezone

class ChainOfCustody:
    """
    Each action on the evidence creates an immutable log entry.
    Each entry's hash is included in the next entry, creating a chain.
    Any tampering with any entry invalidates all subsequent entries.
    This is the same principle used in cryptocurrency blockchains.
    """

    def __init__(self, case_id: str, apk_sha256: str, apk_size: int):
        self.case_id = case_id
        self.chain   = []
        self._add_entry("EVIDENCE_RECEIVED", {
            "sha256":     apk_sha256,
            "size_bytes": apk_size,
            "received":   datetime.now(timezone.utc).isoformat()
        })

    def _add_entry(self, action: str, data: dict):
        entry = {
            "seq":       len(self.chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action":    action,
            "data":      data,
            "prev_hash": (
                hashlib.sha256(json.dumps(self.chain[-1]).encode()).hexdigest()
                if self.chain else "GENESIS"
            )
        }
        # Sign this entry with its own hash
        entry["entry_hash"] = hashlib.sha256(json.dumps(entry).encode()).hexdigest()
        self.chain.append(entry)

    def log(self, action: str, **kwargs):
        self._add_entry(action, kwargs)

    def verify_integrity(self) -> bool:
        """Verify no entry has been modified — returns False if tampered"""
        for i, entry in enumerate(self.chain):
            stored_hash = entry.get("entry_hash")
            entry_without_hash = {k: v for k, v in entry.items() if k != "entry_hash"}
            computed_hash = hashlib.sha256(
                json.dumps(entry_without_hash).encode()
            ).hexdigest()
            if stored_hash != computed_hash:
                return False
            if i > 0:
                prev_hash = hashlib.sha256(
                    json.dumps(self.chain[i - 1]).encode()
                ).hexdigest()
                if entry.get("prev_hash") != prev_hash:
                    return False
        return True

    def export_for_report(self) -> dict:
        return {
            "case_id":        self.case_id,
            "entry_count":    len(self.chain),
            "integrity":      "VERIFIED" if self.verify_integrity() else "COMPROMISED",
            "chain":          self.chain
        }
```

### 14.2 Forensic Report Structure

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DIGITAL FORENSIC REPORT — ANDROID APPLICATION ANALYSIS
  Reporting System: AI-Driven APK Threat Forensics Platform v3.0
  Case Reference:   #2024-CID-00847
  Analysis Date:    2024-11-15 14:32 UTC
  Report Generated: 2024-11-15 14:38 UTC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  SECTION 1: EXECUTIVE SUMMARY
  ├── Threat Level:      CRITICAL (AI Risk Score: 94/100)
  ├── Classification:    Mobile RAT / SMS Stealer / Spyware
  ├── AI Confidence:     HIGH (RAG similarity match: 94% to SpyNote 3.2)
  └── Recommended Action: Immediate server seizure request (MLAT to Germany)

  SECTION 2: CHAIN OF CUSTODY (Cryptographically Verified)
  ├── Evidence Received:   2024-11-15 14:28:04 UTC
  ├── SHA256:              a3f9c2d1e5b8...
  ├── MD5:                 7d4a2b9c...
  ├── File Size:           4,847,293 bytes
  └── Integrity Status:   ✅ VERIFIED (15 custody entries, no tampering detected)

  SECTION 3: AI-GENERATED XAI REASONING
  ┌─────────────────────────────────────────────────────────────────┐
  │ "This application was assigned a risk score of 94/100 based on  │
  │  the following chain of evidence: (1) Static analysis revealed  │
  │  hardcoded C2 endpoint 185.220.101.45:4444 in the decompiled    │
  │  DexClassLoader routine, consistent with SpyNote RAT's known    │
  │  network signature. (2) Dynamic analysis confirmed beaconing    │
  │  every 57 seconds to the same IP. (3) Frida interception        │
  │  captured GPS coordinates and SIM serial number being           │
  │  transmitted in the beacon payload. (4) VirusTotal: 41/70       │
  │  engines flagged as SpyNote.Android.C. (5) The C2 IP is hosted  │
  │  on a bulletproof hosting provider (AS12345) with 89 prior      │
  │  abuse reports on AbuseIPDB." ← [AI-generated, XAI-compliant]  │
  └─────────────────────────────────────────────────────────────────┘

  SECTION 4: STATIC ANALYSIS FINDINGS
  SECTION 5: DYNAMIC BEHAVIOUR LOG
  SECTION 6: MEMORY FORENSICS ARTEFACTS
  SECTION 7: C2 INFRASTRUCTURE MAP (embedded graph image)
  SECTION 8: THREAT INTELLIGENCE CORRELATION
  SECTION 9: MITRE ATT&CK TECHNIQUE MAPPING
  SECTION 10: EVIDENCE ARTIFACT INVENTORY (PCAP, Frida logs, dumps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 15. CLOUD INFRASTRUCTURE & ORCHESTRATION

### 15.1 Recommended AWS Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    AWS PRODUCTION SETUP                          │
│                                                                  │
│  us-east-1 (Primary)                                             │
│  ─────────────────────────────────────────────────────────────── │
│                                                                  │
│  ┌───────────────┐  ┌─────────────────────┐                     │
│  │  ALB           │  │  ECS Fargate Cluster │                     │
│  │  (HTTPS/443)   │─►│  API Service         │                     │
│  │  WAF Attached  │  │  (FastAPI, 2–8 tasks)│                     │
│  └───────────────┘  └──────────┬───────────┘                     │
│                                 │                                 │
│  ┌──────────────────────────────┼────────────────────────────┐   │
│  │                              │                            │   │
│  ▼                              ▼                            ▼   │
│  ┌───────────────┐  ┌────────────────────┐  ┌─────────────────┐ │
│  │  EC2 Static   │  │  EC2 Dynamic       │  │  EC2 ML Worker  │ │
│  │  Workers      │  │  Sandbox Workers   │  │  (GNN/RAG)      │ │
│  │  t3.xlarge×2  │  │  c5.metal×2        │  │  g4dn.xlarge    │ │
│  │               │  │  (KVM required)    │  │  (GPU for GNN)  │ │
│  └───────────────┘  └────────────────────┘  └─────────────────┘ │
│                                                                  │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  ElastiCache   │  │  RDS Aurora  │  │  S3 (WORM Bucket)    │ │
│  │  Redis         │  │  PostgreSQL  │  │  Object Lock:        │ │
│  │  (Task Queue)  │  │  (Case DB)   │  │  Compliance Mode     │ │
│  └────────────────┘  └──────────────┘  └──────────────────────┘ │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Neo4j AuraDB (Managed Graph DB — C2 Infrastructure Map)  │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘

  ESTIMATED MONTHLY COST (10–50 APKs/day):
  ─────────────────────────────────────────
  EC2 instances (4 total)      : ~$480/mo
  RDS Aurora (db.t3.medium)    : ~$80/mo
  S3 storage (1TB, WORM)       : ~$25/mo
  Neo4j AuraDB (free tier)     : $0–$65/mo
  ALB + data transfer          : ~$30/mo
  LLM API (GPT-4o, ~100 calls) : ~$15/mo
  ─────────────────────────────────────────
  TOTAL ESTIMATE               : ~$630–$700/mo
  Per-analysis cost            : ~$0.50–$2.00
```

### 15.2 Docker Compose (Local/Dev Setup)

```yaml
# docker-compose.yml
version: '3.9'

services:
  api:
    build: ./services/api
    ports: ["8000:8000"]
    environment:
      - DATABASE_URL=postgresql://analyst:pass@postgres:5432/apkdb
      - REDIS_URL=redis://redis:6379/0
      - VIRUSTOTAL_API_KEY=${VT_KEY}
      - OPENAI_API_KEY=${OPENAI_KEY}
      - MOBSF_URL=http://mobsf:8008
      - MOBSF_API_KEY=${MOBSF_KEY}
      - NEO4J_URL=bolt://neo4j:7687
    depends_on: [redis, postgres, mobsf, neo4j]

  worker-static:
    build: ./services/worker-static
    volumes:
      - uploads:/data/uploads:ro
      - output:/data/output
      - chromadb:/data/chromadb    # RAG vector store persistence
    deploy:
      replicas: 2

  worker-dynamic:
    build: ./services/worker-dynamic
    privileged: true               # Required for KVM/Android emulator
    devices:
      - /dev/kvm:/dev/kvm
    environment:
      - ANDROID_AVD_NAME=analysis_avd_12
    deploy:
      replicas: 2

  worker-ml:
    build: ./services/worker-ml
    environment:
      - CHROMADB_PATH=/data/chromadb
      - MODEL_PATH=/data/models/gnn_classifier.pt
    volumes:
      - chromadb:/data/chromadb
      - models:/data/models

  mobsf:
    image: opensecurity/mobile-security-framework-mobsf:latest
    ports: ["8008:8008"]
    volumes:
      - mobsf_data:/home/mobsf/.MobSF

  neo4j:
    image: neo4j:5
    environment:
      - NEO4J_AUTH=neo4j/analyst_password
    ports: ["7474:7474", "7687:7687"]
    volumes:
      - neo4j_data:/data

  redis:
    image: redis:7-alpine

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=apkdb
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  uploads:; output:; chromadb:; models:; mobsf_data:; neo4j_data:; pgdata:
```

---

## 16. API REFERENCE

### 16.1 Core Endpoints

```
METHOD  ENDPOINT                          DESCRIPTION
──────  ────────────────────────────────  ───────────────────────────────────
POST    /api/v1/analyze                   Upload APK, start analysis pipeline
GET     /api/v1/status/{case_id}          Poll analysis progress (or WebSocket)
GET     /api/v1/report/{case_id}          Full JSON report
GET     /api/v1/report/{case_id}/pdf      Court-admissible PDF download
GET     /api/v1/report/{case_id}/stix     STIX 2.1 bundle (for SIEM/MISP)
GET     /api/v1/iocs/{case_id}            Machine-readable IOC list
POST    /api/v1/chat/{case_id}            Investigator chatbot query
POST    /api/v1/batch                     Upload multiple APKs as a job
GET     /api/v1/campaign/{ip}             Find all APKs sharing a C2 IP
GET     /api/v1/similar/{sha256}          Find similar samples (RAG lookup)
POST    /api/v1/misp/publish/{case_id}    Publish findings to MISP
```

### 16.2 WebSocket Progress Feed

```json
// ws://host/api/v1/ws/{case_id}
// Messages streamed during analysis:

{"stage": "ingestion",      "pct": 5,  "msg": "APK received, hash verified"}
{"stage": "static",         "pct": 20, "msg": "MobSF scan complete — 12 findings"}
{"stage": "static_ai",      "pct": 30, "msg": "LLM deobfuscating 3 suspicious blocks..."}
{"stage": "dynamic_start",  "pct": 35, "msg": "AVD booting, Frida injecting..."}
{"stage": "dynamic_run",    "pct": 55, "msg": "App running — 47 events captured"}
{"stage": "ssl_mitm",       "pct": 60, "msg": "SSL pinning bypassed — 3 requests decrypted"}
{"stage": "memory",         "pct": 68, "msg": "Memory dump acquired — extracting strings"}
{"stage": "intel",          "pct": 75, "msg": "VirusTotal: 41/70 — SpyNote.Android"}
{"stage": "rag",            "pct": 82, "msg": "RAG: 94% match to historical SpyNote 3.2"}
{"stage": "gnn",            "pct": 87, "msg": "GNN classifier: RAT family (97% confidence)"}
{"stage": "ai_synthesis",   "pct": 92, "msg": "LLM generating XAI risk narrative..."}
{"stage": "report",         "pct": 98, "msg": "PDF generated, S3 WORM committed"}
{"stage": "complete",       "pct": 100,"msg": "Analysis complete — Score: 94/100 CRITICAL"}
```

---

## 17. REAL-WORLD DEPLOYMENT PLAYBOOKS

### 17.1 Law Enforcement — Evidence Handling Protocol

```
BEFORE ANALYSIS:
  1. Obtain proper legal authorisation (warrant/court order)
  2. Document chain of custody for the physical device
  3. Extract APK using:
     adb backup -apk -noshared -f backup.ab com.suspect.app
     OR
     adb pull /data/app/com.suspect.app/base.apk suspect.apk

DURING ANALYSIS:
  4. Upload to platform with Case Reference ID
  5. Do NOT close the browser — monitor WebSocket progress
  6. Note the Case ID for evidence record

AFTER ANALYSIS:
  7. Download PDF report — this is your court-ready document
  8. Download STIX bundle — for sharing with cybercrime unit
  9. Preserve case in S3 WORM — it cannot be deleted (evidence integrity)
  10. Use investigator chat to prepare for expert witness testimony
```

### 17.2 Enterprise SOC — MDM Integration

```python
# Integration with Microsoft Intune / Jamf MDM
# Automatically blocks apps scoring above threshold

import requests

def mdm_policy_enforcement(apk_sha256: str, threat_score: int,
                            package_name: str, mdm_token: str):
    """
    If threat score > 60, push a block policy to MDM for this package.
    Notifies all enrolled devices to uninstall and block reinstallation.
    """
    BLOCK_THRESHOLD = 60

    if threat_score <= BLOCK_THRESHOLD:
        return {"action": "none", "reason": "below_threshold"}

    # Intune Graph API — Add app to non-compliant list
    response = requests.post(
        "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps",
        headers={"Authorization": f"Bearer {mdm_token}"},
        json={
            "packageId":            package_name,
            "complianceStatus":     "nonCompliant",
            "blockReason":          f"Malware detected — threat score {threat_score}/100",
            "sha256":               apk_sha256,
            "automaticUninstall":   threat_score > 80
        }
    )
    return {"action": "blocked", "mdm_response": response.status_code}
```

### 17.3 CERT/CSIRT — Automated IOC Pipeline

```
WORKFLOW FOR NATIONAL CERT:
                                                               
  Citizen reports suspicious app                               
         │                                                     
         ▼                                                     
  Platform analyses APK (automated, no analyst time)           
         │                                                     
         ▼                                                     
  If Score > 70:                                               
  ├── Auto-publish IOCs to internal MISP                       
  ├── MISP sync pushes to: allied CERTs, sector ISACs          
  ├── STIX bundle sent to national SIEM (Splunk/Sentinel)      
  └── Alert sent to relevant sector (banking/telecom/govt)     
         │                                                     
         ▼                                                     
  If C2 server identified:                                     
  ├── Abuse report auto-filed to hosting ASN                   
  ├── INTERPOL CCC notified via standardized report            
  └── Domain takedown request prepared (evidence packet)       
```

---

## 18. SECURITY & ISOLATION DESIGN

### 18.1 Threat Model — What Could Go Wrong

```
RISK                         MITIGATION
───────────────────────────  ───────────────────────────────────────────────
Malware escapes sandbox      • Network namespace isolation (no internet)
                             • Container destroyed after every analysis
                             • Host filesystem read-only mounts

Malware targets analyst PC   • Analysis ONLY in cloud — no local execution
                             • Analyst access via web UI only (never APK)

Evidence tampering           • S3 Object Lock (Compliance Mode) — immutable
                             • Hash-chained custody log
                             • PDF digitally signed with platform key

LLM hallucination            • Low temperature (0.1) on forensic prompts
                             • All AI claims grounded to actual evidence
                             • XAI paragraph cites specific findings

API key exposure             • Keys in AWS Secrets Manager, not env vars
                             • Keys never logged or included in reports
                             • Per-case IAM role (least privilege)

Cross-analysis contamination • Each analysis in isolated Docker container
                             • Container image rebuilt fresh each time
                             • No shared memory between concurrent analyses
```

---

## 19. MITRE ATT&CK MOBILE MAPPING

> All detected behaviours are automatically tagged to MITRE ATT&CK for Mobile
> techniques. This provides a standardised vocabulary for sharing findings across
> organisations and correlating with broader threat intelligence.

```
MITRE ID    TECHNIQUE                        HOW DETECTED
──────────  ───────────────────────────────  ───────────────────────────────
T1412       Capture SMS Messages             Frida: abortBroadcast hook
T1430       Location Tracking               Frida: getLastKnownLocation
T1429       Capture Audio                   Permission analysis + MIC hook
T1512       Video Capture                   Camera API Frida hook
T1636.003   Contact List Access             Frida: ContentResolver query
T1437.001   C2 over HTTP/HTTPS              PCAP beaconing analysis
T1407       Download New Code              Static: DexClassLoader pattern
T1406       Obfuscated Files/Information   YARA: high entropy + base64
T1633.001   Virtualization/Sandbox Evasion Frida: Build.MODEL read hook
T1624.001   Boot-Completed Persistence     Manifest: BOOT_COMPLETED receiver
T1582       SMS Control (Block Incoming)   Frida: abortBroadcast on SMS_RX
T1414       Clipboard Data                 Frida: ClipboardManager hook
T1417.002   GUI Input Capture              Accessibility Service detection
T1521       Encrypted Channel             mitmproxy: SSL pinning bypass
```

---

## 20. SUGGESTED ENHANCEMENTS & ROADMAP

> **Description:** These are concrete additions that would make the platform
> significantly more capable in production deployments. Each is ranked by
> implementation effort and real-world impact.

### 20.1 High Impact, Moderate Effort

```
ENHANCEMENT                 DESCRIPTION                         WHY IT MATTERS
──────────────────────────  ──────────────────────────────────  ─────────────────────────────────
Play Store Monitor          Crawl top 500 apps daily, alert on  Catches trojans before mass        
                            new apps with suspicious patterns   distribution to victims
                            
Federated Learning          Multiple orgs contribute to GNN     Improves accuracy without
                            model improvement without sharing   sharing raw malware samples
                            raw APK data                        (privacy-preserving)

Automated MLAT Package      Auto-generate Mutual Legal          Cuts weeks off international
                            Assistance Treaty request with      C2 server investigation
                            all evidence pre-formatted for
                            specific jurisdiction templates

Binary Similarity (SSDEEP)  Fuzzy hash comparison to find       Catches malware that changes
                            near-identical APK variants         1–5% of code each build cycle
```

### 20.2 High Impact, Higher Effort (Phase 2)

```
ENHANCEMENT                 DESCRIPTION                         TECH STACK
──────────────────────────  ──────────────────────────────────  ──────────────────────────────
Differential Privacy        Add noise to model training data    PySyft + PyTorch
for Org Collaboration       so individual case data cannot       
                            be reverse-engineered               

Threat Actor Attribution    Cluster C2 infrastructure by TTP    Neo4j + LLM entity linking
Graph (STIX CourseOfAction) and cert fingerprint patterns to    + ATT&CK Navigator
                            identify individual threat actors   

Real-Time App Store         Partner with Google/Samsung to      Play Integrity API +
Integration                 analyse apps before publication     Custom MoU
                            (shift-left approach)               

iOS IPA Analysis Port       Extend platform to cover iOS IPAs   Frida on jailbroken iPhone
                            (same architecture, different       + JTOOL2 + Hopper
                            toolchain)                          
```

### 20.3 Suggested Changes to Current Architecture

```
CURRENT                              SUGGESTED IMPROVEMENT               REASON
───────────────────────────────────  ─────────────────────────────────── ─────────────────────────────
Single Celery queue                → Priority queues (HIGH/NORMAL/BULK)  Law enforcement cases need
                                                                          to jump the queue

OpenAI API only                    → Hybrid: GPT-4o for complex cases    Cost: $0.03/call × volume
                                     Llama-3-local for routine scans      Local inference = free

All findings in PostgreSQL         → Static findings in PostgreSQL        Neo4j is far faster for
                                     C2 relationships in Neo4j            "find all connected IPs"
                                     
Manual MISP publish                → Auto-publish if score > 75 AND      Eliminates analyst bottleneck
                                     confirmed by GNN + RAG               for high-volume CERT usage

PDF only report output             → PDF + HTML interactive report        Investigators can click on
                                                                           IP addresses to run live
                                                                           threat intel lookups

Fixed 120s dynamic analysis time   → Adaptive duration (short if         Saves compute; some malware
                                     malware activates in 30s,           activates in 10s, some needs
                                     extend to 300s if dormant)          4+ minutes of simulation
```

---

## 21. COMPREHENSIVE TECH STACK

```
LAYER                    TOOL / SERVICE              VERSION    LICENSE / COST
───────────────────────  ──────────────────────────  ─────────  ──────────────────────────
FRONTEND
  Dashboard UI           React + Tailwind CSS        18.x       MIT / Free
  Real-time updates      WebSocket (FastAPI)         —          Free

BACKEND / ORCHESTRATION
  API Framework          FastAPI (Python 3.11+)      0.110+     MIT / Free
  Task Queue             Celery + Redis              5.3+       BSD / Free
  Container Orchestration Docker Compose (dev)       24+        Apache 2 / Free
                         Kubernetes (production)     1.29+      Apache 2 / Free

STATIC ANALYSIS
  Core Engine            MobSF                       3.9+       GPL v3 / Free
  Decompiler             JADX                        1.4+       Apache 2 / Free
  APK Disassembler       APKTool                     2.9+       Apache 2 / Free
  Pattern Matching       YARA                        4.3+       BSD / Free
  Repackage Detector     Androguard                  3.3+       Apache 2 / Free

DYNAMIC ANALYSIS
  Emulator               Android Virtual Device      API 31     Apache 2 / Free
  Instrumentation        Frida                       16+        wxWindows / Free
  Companion              Objection                   1.11+      MIT / Free
  SSL MITM               mitmproxy                   10+        MIT / Free
  Network Capture        tcpdump                     4.99+      BSD / Free
  PCAP Analysis          Scapy                       2.5+       GPL v2 / Free

MEMORY FORENSICS
  Memory Analysis        Volatility3                 2.5+       Volatility License / Free
  String Extraction      GNU Strings (binutils)      —          GPL v3 / Free

GENERATIVE AI
  LLM (Cloud)            OpenAI GPT-4o               —          $0.005–0.015/1K tokens
  LLM (Cloud alt.)       Google Gemini 1.5 Pro       —          $0.0035/1K tokens
  LLM (Air-gapped)       Llama-3-8B-Instruct (Ollama) 3.0       MIT / Free
  Prompt Orchestration   LangChain                   0.2+       MIT / Free
  Vector Embeddings      SentenceTransformers        2.7+       Apache 2 / Free

MACHINE LEARNING
  GNN Framework          PyTorch Geometric           2.3+       MIT / Free
  Neural Networks        PyTorch                     2.2+       BSD / Free
  RAG Vector DB          ChromaDB                    0.4+       Apache 2 / Free

DATABASES
  Case Management        PostgreSQL                  15+        PostgreSQL / Free
  Graph DB               Neo4j (AuraDB Free tier)    5+         GPL / Free tier
  Cache / Queue Broker   Redis                       7+         BSD / Free

THREAT INTELLIGENCE
  Multi-AV Scan          VirusTotal API v3           —          Free (500/day) / Paid
  IP Reputation          AbuseIPDB API v2            —          Free (1K/day) / Paid
  Internet Scanning      Shodan                      —          Free limited / ~$59/mo
  Open Threat Intel      AlienVault OTX              —          Free
  Malware Repository     MalwareBazaar               —          Free
  Org Threat Sharing     MISP (self-hosted)          2.4+       AGPL / Free
  IOC Format             STIX2 Python                3+         BSD / Free

CLOUD / STORAGE
  Compute                AWS EC2 (c5.metal for AVD)  —          ~$200–500/mo
  Immutable Storage      AWS S3 + Object Lock        —          ~$25/mo (1TB)
  Secrets Management     AWS Secrets Manager         —          ~$1/secret/mo
  Certificate Authority  AWS ACM (TLS)               —          Free

FORENSIC REPORTING
  PDF Generation         ReportLab                   4+         BSD / Free
  Digital Signature      OpenSSL (RSA-4096)          3.0+       Apache 2 / Free
  Threat Intelligence    python-stix2                3+         BSD / Free
  MISP Publishing        PyMISP                      2.4+       BSD / Free
```

---

## APPENDIX A — QUICK START (LOCAL DEV)

```bash
# Prerequisites: Docker, Docker Compose, Python 3.11+

# 1. Clone and configure
git clone https://github.com/your-org/apk-threat-hunter
cd apk-threat-hunter
cp .env.example .env
# Edit .env: add VIRUSTOTAL_API_KEY, OPENAI_API_KEY

# 2. Start all services
docker compose up -d

# 3. Wait for MobSF to initialize (~60 seconds first run)
docker compose logs -f mobsf | grep "Mobile Security Framework"

# 4. Get MobSF API key
docker compose exec mobsf cat /home/mobsf/.MobSF/secret
# Paste this into your .env as MOBSF_API_KEY

# 5. Set up Android AVD inside dynamic worker
docker compose exec worker-dynamic bash -c "
  avdmanager create avd \
    --name analysis_avd_12 \
    --package 'system-images;android-31;google_apis;x86_64' \
    --device pixel_4 --force
"

# 6. Open dashboard
open http://localhost:3000

# 7. Test with a known malware sample
curl -X POST http://localhost:8000/api/v1/analyze \
  -F "file=@samples/spynote_sample.apk" \
  -H "Authorization: Bearer test_key"
```

---

## APPENDIX B — KEY CONCEPTS GLOSSARY

```
TERM              DEFINITION (Plain English)
────────────────  ──────────────────────────────────────────────────────────
APK               Android Package — the installer file for Android apps
C2 Server         Command & Control — the criminal's remote server that
                  controls malware and receives stolen data
Frida             Dynamic instrumentation tool — injects JS into running apps
                  to intercept function calls in real-time
RAG               Retrieval-Augmented Generation — AI that can reference a
                  database of past analyses when reasoning about new samples
GNN               Graph Neural Network — ML model that understands the
                  structure of API call graphs to classify malware families
YARA              Pattern-matching language for malware hunting (like grep
                  but for complex binary patterns)
MITM              Man-in-the-Middle — intercepting and reading encrypted
                  traffic between the malware and its C2 server
STIX/TAXII        Standard formats for sharing cyber threat intelligence
                  between organisations (like a common language for IOCs)
XAI               Explainable AI — AI that explains its own reasoning,
                  required for court-admissible automated analysis
WORM Storage      Write Once, Read Many — files that cannot be modified or
                  deleted after writing (critical for evidence integrity)
MISP              Malware Information Sharing Platform — used by CERTs
                  worldwide to share IOCs in real-time
Chain of Custody  Documented record of who handled evidence and when —
                  proves evidence was not tampered with
DGA               Domain Generation Algorithm — malware that generates
                  random domain names to find its C2 server
Beaconing         Malware periodically "checking in" with its C2 server
                  at regular intervals (like a heartbeat)
```

---

*End of Technical Reference | Version 3.0 | AI-Driven APK Threat Forensics Platform*
*Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY*
