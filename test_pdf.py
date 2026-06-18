from app.reporting.pdf_generator import generate_report_pdf

demo_data = {
    "case_id": "TEST1234",
    "package_name": "com.evil.app.testlongpackagename.verylongindeed.test",
    "apk_sha256": "8d3e23f0...longhash...",
    "threat_score": 85,
    "classification": "CRITICAL",
    "malware_family": "Ransomware / RAT",
    "ai_analysis": {
        "risk_assessment": {
            "chain_of_reasoning": "This app is extremely malicious. It attempts to steal SMS, intercept notifications, and use accessibility services to perform overlay attacks on banking apps. Highly obfuscated using an unknown packer."
        },
        "behavior_context": {
            "behavior_narrative": "At runtime, the app hid its icon, connected to a Telegram bot, and attempted to load a dynamic dex file."
        }
    },
    "static_analysis": {
        "semantic_capabilities": [
            "Remote Access Trojan (RAT)",
            "Screen Locker / Ransomware Module",
            "Accessibility Service Abuse"
        ],
        "obfuscation_score": 8,
        "yara_hits": 3,
        "dangerous_permissions": ["android.permission.SEND_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"]
    },
    "dynamic_analysis": {
        "events": [
            {"type": "crypto", "algorithm": "AES/CBC/PKCS5Padding", "key_base64": "SGVsbG8gV29ybGQ="},
            {"type": "sms", "destination": "+1234567890", "content": "Stolen credentials..."},
            {"type": "file_access", "path": "/data/data/com.bank.app/databases/users.db"}
        ] * 10  # simulate 30 events, only 20 should show
    },
    "c2_infrastructure": [
        {"ip": "1.2.3.4", "country": "RU", "domain": "evil.com", "composite_risk": 85},
        {"ip": "8.8.8.8", "country": "US", "domain": "dns.google", "composite_risk": 5}
    ],
    "custody_chain": {
        "integrity": "VERIFIED",
        "entry_count": 42
    }
}

path = generate_report_pdf(demo_data, "test_output.pdf")
print(f"Generated test PDF: {path}")
