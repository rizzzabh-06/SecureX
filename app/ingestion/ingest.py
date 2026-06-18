"""
APK Ingestion Layer — accepts APK from 3 sources:
1. Direct file upload
2. URL download (WhatsApp links, phishing URLs)
3. QR code image → extract URL → download APK

All three produce the same output: a local .apk file + SHA256 hash.
"""

import hashlib
import io
import zipfile
from pathlib import Path
from typing import Optional

import aiohttp

from app.config import settings


class IngestAPK:
    """
    Unified APK ingestion from multiple sources.
    Validates the file is a real APK and computes forensic hashes.
    """

    def __init__(self):
        self.upload_dir = Path(settings.UPLOAD_DIR)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    # ── Source 1: File Upload ──────────────────────────────────────
    def from_file(self, file_bytes: bytes, filename: str) -> dict:
        """Ingest APK from direct file upload."""
        if not self._is_valid_apk(file_bytes):
            raise ValueError("Uploaded file is not a valid APK (missing AndroidManifest.xml)")

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        dest = self.upload_dir / f"{sha256}.apk"
        dest.write_bytes(file_bytes)
        return self._build_result(dest, sha256, file_bytes, "file_upload")

    # ── Source 2: URL Download ─────────────────────────────────────
    async def from_url(self, url: str) -> dict:
        """
        Download APK from any URL.
        Handles WhatsApp share links, phishing URLs, and direct download links.
        Banks' fraud teams get phishing links — not APK files.
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status != 200:
                    raise ValueError(f"Failed to download: HTTP {resp.status}")
                content = await resp.read()

        if not self._is_valid_apk(content):
            raise ValueError("Downloaded file is not a valid APK")

        sha256 = hashlib.sha256(content).hexdigest()
        dest = self.upload_dir / f"{sha256}.apk"
        dest.write_bytes(content)
        return self._build_result(dest, sha256, content, "url_download", source_url=url)

    # ── Source 3: QR Code Image ────────────────────────────────────
    async def from_qr_image(self, image_bytes: bytes) -> dict:
        """
        Decode QR code → extract URL → download APK.

        Real-world usage: Fraudulent APKs are distributed via QR codes
        on fake pamphlets, WhatsApp images, or fake bank communications.
        An investigator photographs the QR and uploads the image directly.
        """
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except ImportError:
            raise ValueError("QR code scanning requires 'pyzbar' and 'Pillow' packages")

        img = Image.open(io.BytesIO(image_bytes))
        codes = decode(img)

        if not codes:
            raise ValueError("No QR code found in image")

        url = codes[0].data.decode("utf-8")
        if not url.startswith("http"):
            raise ValueError(f"QR code doesn't contain a URL: {url}")

        return await self.from_url(url)

    # ── Helpers ────────────────────────────────────────────────────
    def _is_valid_apk(self, data: bytes) -> bool:
        """Verify the file is a valid APK (ZIP with AndroidManifest.xml)."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return "AndroidManifest.xml" in z.namelist()
        except (zipfile.BadZipFile, Exception):
            return False

    def _build_result(self, path: Path, sha256: str, raw_bytes: bytes,
                      source: str, **meta) -> dict:
        """Build standardized ingestion result."""
        return {
            "path": str(path),
            "sha256": sha256,
            "md5": hashlib.md5(raw_bytes).hexdigest(),
            "size_bytes": len(raw_bytes),
            "source": source,
            **meta
        }
