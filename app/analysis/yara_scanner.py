"""
YARA Scanner for APK files
Scans DEX content and embedded files against YARA rules.
"""
import zipfile
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


class YARAScanner:
    """Scans APK content against YARA rules."""

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile YARA rules from file."""
        if not YARA_AVAILABLE:
            logger.warning("yara-python not available - YARA scanning disabled")
            return

        rules_path = Path(self.rules_path)
        if not rules_path.exists():
            logger.warning(f"YARA rules path not found: {self.rules_path}")
            return

        try:
            if rules_path.is_file():
                self.rules = yara.compile(filepath=str(rules_path))
            elif rules_path.is_dir():
                filepaths = {f.stem: str(f) for f in rules_path.glob("*.yar")}
                if not filepaths:
                    logger.warning(f"No .yar files found in {self.rules_path}")
                    return
                self.rules = yara.compile(filepaths=filepaths)
            logger.info(f"YARA rules compiled from {self.rules_path}")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

    def scan_apk(self, apk_path: str) -> list[dict]:
        """Scan APK file and all its contents against YARA rules."""
        if not YARA_AVAILABLE or not self.rules:
            return []

        matches = []

        # Scan the entire APK as a binary
        try:
            with open(apk_path, "rb") as f:
                data = f.read()
            apk_matches = self.rules.match(data=data)
            for match in apk_matches:
                matches.append(self._format_match(match, "APK Binary"))
        except Exception as e:
            logger.warning(f"YARA scan error on APK: {e}")

        # Scan individual files within the APK
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for fname in zf.namelist():
                    if not fname.endswith((".dex", ".so", ".jar", ".apk")):
                        continue
                    try:
                        data = zf.read(fname)
                        file_matches = self.rules.match(data=data)
                        for match in file_matches:
                            entry = self._format_match(match, fname)
                            # Avoid duplicate rule matches
                            if not any(m["rule"] == entry["rule"] for m in matches):
                                matches.append(entry)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"YARA ZIP scan error: {e}")

        return matches

    def _format_match(self, match, source: str) -> dict:
        """Format a YARA match result."""
        result = {
            "rule": match.rule,
            "source": source,
            "tags": list(match.tags),
            "meta": {},
            "strings": [],
        }

        # Extract meta
        for key, val in match.meta.items():
            result["meta"][key] = val

        # Extract matched strings (limited)
        seen = set()
        for string_match in match.strings[:10]:
            for instance in string_match.instances[:3]:
                try:
                    val = instance.matched_data.decode("utf-8", errors="replace")[:100]
                    if val not in seen:
                        seen.add(val)
                        result["strings"].append(val)
                except Exception:
                    pass

        return result
