from app.analysis.static_analyzer import StaticAnalyzer
from pathlib import Path

# Provide path to some actual APK or mock it using an existing file
apk_path = "/home/rishabh/Downloads/com.amtso.mobiletestfile.apk"
if not Path(apk_path).exists():
    # fallback to just testing if it initializes correctly
    print(f"Skipping actual scan since {apk_path} missing")
else:
    analyzer = StaticAnalyzer()
    matches = analyzer._yara_scan(apk_path)
    print("Matches:", matches)
