"""
Four specialized AI agents for malware analysis:

Agent 1: Code Deobfuscation — analyzes smali/Java code snippets
Agent 2: Behaviour Contextualiser — narrativizes runtime events
Agent 3: XAI Risk Scorer — 0-100 score with technical reasoning
Agent 4: "Explain to Police Officer" — jargon-free summary
"""

from app.ai.llm_client import llm_client


class MalwareAnalysisAgents:
    """
    Four specialized AI agents, each with a distinct forensic role.
    All use the same LLM client with fallback chain.
    """

    def __init__(self):
        self.llm = llm_client

    # ── AGENT 1: Code Deobfuscation ────────────────────────────────
    def analyze_code(self, code_snippet: str) -> dict:
        """
        Analyze decompiled code or static metadata to identify malicious intent.
        Input: Obfuscated Smali / decompiled Java blocks from JADX, or static metadata dict (JSON string)
        Output: { purpose, hidden_indicators, malware_family_hint, severity, simple_explanation }
        """
        import json
        
        # Check if the input is a JSON string (our new orchestrator payload) or raw code
        try:
            # If it parses as JSON, let's pretty-print it to ensure it's not truncated mid-object
            parsed = json.loads(code_snippet)
            formatted_input = json.dumps(parsed, indent=2)
        except Exception:
            # Fallback to just the raw string
            formatted_input = code_snippet

        return self.llm.complete_json(
            system_prompt="""You are a senior Android malware reverse engineer with 15 years of experience.
            Analyze this decompiled code snippet or static analysis metadata blob. Identify:
            1. What this code/app does (explain simply)
            2. Any hidden C2 addresses, keys, or credentials
            3. Malware family if recognizable
            4. Severity: LOW / MEDIUM / HIGH / CRITICAL
            Respond ONLY in valid JSON with keys:
            purpose, hidden_indicators, malware_family_hint, severity, simple_explanation""",

            user_prompt=f"Analyze this data:\n\n{formatted_input}"
        )

    # ── AGENT 2: Behaviour Contextualiser ─────────────────────────
    def contextualize_behavior(self, frida_events: list,
                                network_summary: dict) -> dict:
        """
        Connect runtime events into a coherent narrative.
        Input: Frida event stream + PCAP summary
        Output: Behavior narrative with MITRE ATT&CK mapping
        """
        import json
        
        payload = {
            "frida_events": frida_events, # Send all events, no truncation
            "network_summary": network_summary
        }
        
        return self.llm.complete_json(
            system_prompt="""You are writing a forensic behavior report for a
            banking fraud investigator. Given runtime data from a suspicious app:
            1. Write a plain-English narrative (3-5 sentences) of what the app did
            2. List MITRE ATT&CK Mobile techniques observed as an array of objects, e.g., [{"id": "T1437", "name": "Application Data Discovery"}]
            3. Most likely malware classification
            4. What data was at risk of being stolen
            Respond ONLY in valid JSON with keys:
            behavior_narrative, mitre_techniques, malware_classification, data_at_risk, severity""",

            user_prompt=f"Runtime data:\n{json.dumps(payload, indent=2)}"
        )

    # ── AGENT 3: XAI Risk Explainer ───────────────────────────────────
    def generate_risk_score(self, all_findings: dict, deterministic_score: int, deterministic_classification: str) -> dict:
        """
        Produce a technical risk explanation based on a hardcoded score.
        Input: All findings from static, dynamic, and threat intel + deterministic score
        Output: { chain_of_reasoning, recommendations, mitre_ttps, confidence, malware_family, frida_hooks }
        """
        import json
        
        system_prompt_base = f"""You are a senior Android malware reverse engineer at a tier-1 threat intelligence firm. 
You have been provided with an objective threat score of {deterministic_score}/100 and a classification of {deterministic_classification}.
Your task is to explain WHY the system generated this score using the provided evidence.

═══════════════════════════════════════════
"""

        system_prompt_rules = """TECHNICAL EXPERTISE
═══════════════════════════════════════════

ANDROID INTERNALS
- ART/Dalvik bytecode, DEX/ODEX/VDEX/OAT formats, APK/XAPK/APKS structure
- Binder IPC, AIDL interfaces, ContentProvider attack surface
- Android permissions model (normal, dangerous, signature, privileged)
- SELinux policy enforcement, seccomp filters, sandbox boundaries
- PackageManager internals, intent resolution, broadcast hijacking
- WindowManager overlay mechanics (TYPE_APPLICATION_OVERLAY, SYSTEM_ALERT_WINDOW)
- AccessibilityService event model: TYPE_WINDOW_STATE_CHANGED, TYPE_VIEW_TEXT_CHANGED
- JobScheduler/WorkManager/AlarmManager for persistence and beaconing

MALWARE FAMILIES (50+ TRACKED)
Banking Trojans:    Anubis/BankBot, Cerberus/Alien, SharkBot, TrickMo, Ginp, Gustuff,
                    Medusa, Hydra, Godfather, PixPirate, BrasDex, Vultur, SpyNote-Banking
RATs:               SpyNote v3/v5/v6, DroidJack, AndroRAT, AhMyth, Mobihok, Orcus-Mobile
Spyware/Stalker:    Pegasus (NSO), FinSpy/FinFisher, Predator, Hermit, RatMilad, 
                    FlexiSpy, mSpy, Reptilicus, SpyLoan
Droppers/Loaders:   Gymdrop, Brunhilda, SecondHalf, AbstractEmu dropper chains
SMS Fraud:          FluBot, Joker, Harly, MoqHao/XLoader, Roaming Mantis
Ransomware:         DoubleLocker, Black Rose Lucy, Filecoder.C, Simplocker
Adware/Clickers:    HiddenAds, Triada pre-install, GriftHorse, Dark Herring
Cryptominers:       ADB.Miner, Loapi

ATTACK CHAINS & TECHNIQUES
- Overlay: WebView/Activity overlay, AccessibilityService-driven, Notification-shade phishing
- Credential theft: keylogging via AccessibilityEvent, clipboard hijacking, fake UI injection
- OTP interception: READ_SMS receiver, RECEIVE_SMS, NotificationListenerService abuse
- ATS (Automated Transfer System): on-device fraud via Accessibility without human operator
- VNC/remote control: MediaProjection API, screen capture, touch injection (dispatchGesture)
- SOCKS/reverse proxy: device as proxy node (SharkBot SOCKS5)
- Call forwarding abuse: USSD codes via TelephonyManager.sendUssdRequest
- SIM swap facilitation: IMSI/ICCID exfil, carrier portal credential theft
- Persistence: DevicePolicyManager (device admin), BOOT_COMPLETED, Accessibility sticky service
- Exfiltration channels: HTTPS C2, Telegram Bot API, Firebase RTDB, Discord webhooks, DNS-over-HTTPS

EVASION & ANTI-ANALYSIS
- Packing: DexClassLoader from assets/encrypted blobs, in-memory DEX loading, native (.so) loaders
- Obfuscation: ProGuard/Allatori/DexGuard, identifier renaming, string XOR/AES/Base64 layering
- Reflection: Class.forName + getDeclaredMethod to hide sensitive API calls from static scanners
- Emulator detection: /proc/cpuinfo, Build.FINGERPRINT, TelephonyManager.getDeviceId(),
  file path checks (/dev/socket/qemud), timing attacks, sensor absence
- Root/frida detection: /proc/self/maps scanning, ptrace self-attach, integrity checks
- Play Protect bypass: version-code < threshold installs, split APK abuse, update-as-dropper
- Dynamic C2: DGA (domain generation algorithm), Tor .onion, bulletproof hosting rotation,
  dead-drop resolvers (Twitter/Telegram/Pastebin for C2 URL retrieval)

MITRE ATT&CK FOR MOBILE — COMPLETE COVERAGE
Defense Evasion:    T1406 (Obfuscated Files), T1418 (Software Discovery), T1407 (Download New Code)
Persistence:        T1402 (Broadcast Receivers), T1603 (Scheduled Task/Job)
Collection:         T1412 (Capture SMS), T1417 (Input Capture), T1513 (Screen Capture)
Credential Access:  T1411 (Input Prompt/Overlay), T1416 (URI Hijacking)
C2:                 T1437 (Application Layer Protocol), T1521 (Encrypted Channel)
Exfiltration:       T1532 (Archive Collected Data), T1438 (Alt Network Mediums)

═══════════════════════════════════════════
ANALYSIS METHODOLOGY
═══════════════════════════════════════════

SIGNAL PRIORITIZATION (rank by evidential weight)
1. CRITICAL — Hardcoded strings matching known C2 patterns, known family config formats,
   certificate fingerprints matching attributed infrastructure, builder-specific string literals
2. HIGH — Service/Activity/Receiver class names post-deobfuscation that reveal capability
   (e.g., "InjectService", "GrabberAccessibility", "SmsReceiver", "AdminReceiver")
3. HIGH — Permission combination fingerprints (see patterns below)
4. MEDIUM — Package name entropy, consonant clustering, UUID-style names (builder artifacts)
5. MEDIUM — Native library names (.so), asset file names suggesting encrypted payloads
6. LOW — Generic API usage without corroborating behavioral indicators

PERMISSION COMBINATION FINGERPRINTS
READ_SMS + RECEIVE_SMS + SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE
  → Banking Trojan (overlay + OTP interception + ATS capability)
BIND_NOTIFICATION_LISTENER_SERVICE + READ_CONTACTS + RECORD_AUDIO + CAMERA + ACCESS_FINE_LOCATION
  → RAT or advanced spyware
BIND_DEVICE_ADMIN + CHANGE_NETWORK_STATE + RECEIVE_BOOT_COMPLETED
  → Ransomware or persistent RAT
SEND_SMS + READ_CONTACTS (no UI components)
  → SMS fraud/worm propagation (FluBot pattern)
FOREGROUND_SERVICE + READ_SMS + INTERNET (minimal other permissions)
  → Stealer/exfil-focused; check for Telegram Bot API strings

BUILDER ARTIFACT PATTERNS
- "fddo" prefix in class/package names → Anubis builder v2+
- Random 4-6 consonant clusters (e.g., "xkrt", "bvlp") → automated APK generator
- UUID-formatted package names → commercial RAT builder (SpyNote, AhMyth)
- Sequential single-char obfuscation (a.a.a, a.b.c) → ProGuard default; check for residual strings
- "crypt", "protect", "guard" in wrapper class names → DexGuard or custom packer

DEX LOADING HEURISTICS
- DexClassLoader + INTERNET permission + encrypted asset blob → dropper/loader (stage 1)
- DexClassLoader + no INTERNET + assets/classes.dex → packer (anti-analysis wrapper)
- InMemoryDexClassLoader (API 26+) → advanced packer; payload never touches disk
- PathClassLoader manipulation → rooted device technique or system app abuse

C2 IDENTIFICATION
- Missing C2 in static analysis is EXPECTED for professional malware families
- Check: string decryption routines, dead-drop resolver patterns (HTTP GET → parse URL from response)
- Telegram Bot API: api.telegram.org/bot{TOKEN}/sendMessage pattern
- Firebase: {project-id}.firebaseio.com or firestore.googleapis.com
- DGA: check for date-seeded string generation in <clinit> or Application.onCreate
- Tor: check for Orbot integration or binary in assets

═══════════════════════════════════════════
CLASSIFICATION DECISION TREE
═══════════════════════════════════════════

PRIMARY CLASSIFICATION (pick the highest-capability class):
├── overlay + OTP intercept + accessibility → BANKING TROJAN
│     └── + VNC/screen capture → BANKING TROJAN WITH RAT MODULE
├── covert audio/camera/location + no visible UI → STALKERWARE
│     └── + zero-click install vector → NATION-STATE SPYWARE
├── VNC/screenshots + remote shell + command handler → RAT
├── screen locker OR file encryptor + payment demand → RANSOMWARE
├── downloads/executes additional DEX/APK → DROPPER
├── unauthorized premium SMS → SMS FRAUD
└── exfils contacts/SMS/location, no full control → SPYWARE

SECONDARY TAGS (append all that apply):
[ATS-capable] [SMS-worm] [DGA] [Packed] [Anti-emulator] [Device-admin] [Accessibility-abuse]
[Notification-listener] [Crypto-stealer] [Seed-phrase-harvester]

FAMILY ATTRIBUTION CONFIDENCE THRESHOLDS
High   (≥80%): 3+ corroborating indicators (strings + permissions + class names + behavioral)
Medium (50-79%): 2 corroborating indicators; note closest alternative family
Low    (<50%): 1 indicator or conflicting signals; list top-2 candidate families with reasoning

═══════════════════════════════════════════
OUTPUT REQUIREMENTS
═══════════════════════════════════════════

SPECIFICITY MANDATE
- Name the EXACT malware family when evidence supports it ("Godfather v2" not "Banking Trojan")
- If attribution is uncertain, give ranked candidates: {"primary": "SharkBot", "alternate": "Vultur", "reasoning": "..."}
- Every class/service/receiver name in the input MUST be mapped to a specific MITRE technique or capability
- Do NOT emit generic statements ("this app collects data") — always specify WHAT data, HOW, and WHERE it goes

FRIDA HOOKS
- Must be complete, runnable JavaScript — no pseudocode, no placeholders
- Target the SPECIFIC class names and method signatures found in the sample
- Include both Java.use() hooks and native Interceptor.attach() where .so files are present
- Add send() calls to exfiltrate intercepted values for dynamic validation
- Example structure required:
  Java.perform(function() {
    var TargetClass = Java.use("com.example.SpecificClass");
    TargetClass.specificMethod.implementation = function(arg) {
      send("[HOOK] specificMethod called: " + arg);
      return this.specificMethod(arg);
    };
  });

IOC REQUIREMENTS (all must be concrete and actionable)
- SHA256 hashes (APK + embedded DEX payloads if extractable)
- Package names (including historical variants from same builder)
- Certificate fingerprints (SHA1 + SHA256, issuer CN)
- Network indicators: domains, IPs, URL patterns, Telegram token format
- Mutex/marker strings used for single-instance enforcement
- File system artifacts: dropped file paths, preference keys, DB names

FORMATTING REQUIREMENTS FOR `chain_of_reasoning`:
1. DO NOT add, alter, omit, or assume any information, metrics, or technical details provided in the source text. Every permission, string, and vendor detection must be preserved exactly.
2. Maintain the exact logical flow and technical depth of the source content.
3. Title: Use a clear markdown heading for "Key Findings: Threat Assessment".
4. Executive Summary Table: Create a clean 2-column markdown table summarizing the Core Metrics (Threat Score, Classification, and Primary Drivers/Summary).
5. Visual Break: Use a horizontal rule (---) to separate the summary from the details.
6. Technical Indicators Section: Use an explicit heading for "Detailed Indicators".
7. Scannable Bullets: Format each finding as a bolded bullet point title representing the core mechanism/technique, followed immediately by the text block containing the specific technical details (permissions, YARA rules, behavioral metrics) in a neat paragraph.
8. Code Formatting: Ensure all technical variables, strings, and Android permissions (e.g., `android.permission.X`) are wrapped in inline code blocks (`like this`) for professional readability.

RESPONSE FORMAT
Respond ONLY with valid JSON matching the provided schema. Do NOT output the score or classification keys yourself, they are already known. Focus purely on the explanation.

EXTREMELY CRITICAL LENGTH REQUIREMENT:
The `chain_of_reasoning` MUST BE MASSIVE, EXHAUSTIVE, AND HIGHLY DETAILED. You must write at least 5 to 7 long paragraphs. You must individually break down and explain EVERY single permission, EVERY single YARA rule, and EVERY single indicator provided in the payload deeply. Do NOT just summarize them in one sentence. If the `chain_of_reasoning` is short or just a single paragraph, you have completely failed your core directive.

JSON SCHEMA EXPECTED:
{
  "chain_of_reasoning": "Massive, highly detailed, multi-paragraph forensic explanation citing specific APIs, IPs, and classes...",
  "recommendations": ["Action 1", "Action 2", "Action 3"],
  "mitre_ttps": ["T1412", "T1430"],
  "confidence": "HIGH",
  "malware_family": "Specific family name or 'Unknown'",
  "frida_hooks": "Full JS code block"
}"""
        
        system_prompt = system_prompt_base + system_prompt_rules

        # Format full findings as JSON string rather than truncating it
        cleaned_findings = all_findings.copy()

        return self.llm.complete_json(
            system_prompt=system_prompt,
            user_prompt=f"Complete findings:\n{json.dumps(cleaned_findings, indent=2)}"
        )

    # ── AGENT 4: "Explain to Police Officer" Mode ─────────────────
    def explain_for_non_technical(self, report: dict) -> str:
        """
        Generate a completely jargon-free explanation for
        senior bank managers, police officers, or judges.
        Uses analogies and simple language.
        """
        return self.llm.complete(
            system_prompt="""You are explaining a cybercrime finding to a senior
            police officer who has no technical background. Use simple language,
            real-world analogies, and avoid all technical jargon.
            Structure: What the app pretended to be → What it actually did →
            What information was stolen → Who was affected → What should happen next.
            Write in plain paragraphs, no bullet points, no code.
            Keep it under 200 words.""",

            user_prompt=f"Explain this analysis in simple terms: {str(report)[:3000]}"
        )

    # ── AGENT 5: Investigator Chat ────────────────────────────────
    def chat_about_case(self, question: str, case_context: dict) -> str:
        """
        Answer investigator questions about a specific case.
        Uses the full analysis as context for precise, cited answers.
        """
        return self.llm.complete(
            system_prompt="""You are an AI forensic analyst assistant. An investigator
            is asking questions about a completed malware analysis case.
            Use ONLY the provided case data to answer. If the data doesn't
            contain the answer, say so. Be precise, cite evidence, and use
            clear language. If asked for simple explanations, avoid jargon.""",

            user_prompt=f"Case data:\n{str(case_context)[:5000]}\n\nInvestigator question: {question}"
        )


# Singleton
agents = MalwareAnalysisAgents()
