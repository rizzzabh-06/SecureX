"""
Supabase database client and helpers.
Uses Supabase free tier (500MB DB, 1GB Storage).
Falls back to local JSON storage if Supabase is not configured.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.config import settings


class Database:
    """
    Database abstraction layer.
    Primary: Supabase (cloud, free tier)
    Fallback: Local JSON file storage (if Supabase not configured)
    """

    def __init__(self):
        self._supabase = None
        self._local_dir = Path("./local_db")
        self._init_storage()

    def _init_storage(self):
        """Initialize Supabase client or local fallback."""
        if settings.SUPABASE_URL and settings.SUPABASE_KEY and \
           "your-project" not in settings.SUPABASE_URL:
            try:
                from supabase import create_client
                self._supabase = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_SERVICE_KEY or settings.SUPABASE_KEY
                )
                print("[DB] Connected to Supabase")
            except Exception as e:
                print(f"[DB] Supabase connection failed: {e}")
                print("[DB] Falling back to local JSON storage")
                self._setup_local()
        else:
            print("[DB] Supabase not configured — using local JSON storage")
            self._setup_local()

    def _setup_local(self):
        """Setup local JSON file storage as fallback."""
        self._local_dir.mkdir(parents=True, exist_ok=True)
        for table in ["cases", "findings", "threat_intel_cache", "custody_chain"]:
            f = self._local_dir / f"{table}.json"
            if not f.exists():
                f.write_text("[]")

    # === CASES ===

    def create_case(self, case_data: dict) -> dict:
        """Create a new analysis case."""
        case_data["id"] = case_data.get("id", str(uuid.uuid4()))
        case_data["created_at"] = datetime.now(timezone.utc).isoformat()
        case_data["status"] = case_data.get("status", "pending")

        if self._supabase:
            try:
                result = self._supabase.table("cases").insert(case_data).execute()
                return result.data[0] if result.data else case_data
            except Exception as e:
                print(f"[DB] Supabase error in create_case: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                return self._local_insert("cases", case_data)
        else:
            return self._local_insert("cases", case_data)

    def update_case(self, case_id: str, updates: dict) -> dict:
        """Update an existing case."""
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        if self._supabase:
            try:
                result = self._supabase.table("cases").update(updates).eq("id", case_id).execute()
                return result.data[0] if result.data else updates
            except Exception as e:
                print(f"[DB] Supabase error in update_case: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                return self._local_update("cases", case_id, updates)
        else:
            return self._local_update("cases", case_id, updates)

    def get_case(self, case_id: str) -> Optional[dict]:
        """Get a case by ID."""
        if self._supabase:
            try:
                result = self._supabase.table("cases").select("*").eq("id", case_id).execute()
                return result.data[0] if result.data else None
            except Exception as e:
                print(f"[DB] Supabase error in get_case: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                return self._local_get("cases", case_id)
        else:
            return self._local_get("cases", case_id)

    def list_cases(self, limit: int = 20) -> list:
        """List recent cases."""
        if self._supabase:
            try:
                result = (self._supabase.table("cases")
                          .select("*")
                          .order("created_at", desc=True)
                          .limit(limit)
                          .execute())
                return result.data or []
            except Exception as e:
                print(f"[DB] Supabase error in list_cases: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                return self._local_list("cases", limit)
        else:
            return self._local_list("cases", limit)

    # === FINDINGS ===

    def save_findings(self, case_id: str, findings: dict) -> dict:
        """Save analysis findings for a case."""
        record = {
            "id": str(uuid.uuid4()),
            "case_id": case_id,
            "findings": json.dumps(findings) if isinstance(findings, dict) else findings,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        if self._supabase:
            try:
                result = self._supabase.table("findings").insert(record).execute()
                return result.data[0] if result.data else record
            except Exception as e:
                print(f"[DB] Supabase error in save_findings: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                return self._local_insert("findings", record)
        else:
            return self._local_insert("findings", record)

    def get_findings(self, case_id: str) -> Optional[dict]:
        """Get findings for a case."""
        if self._supabase:
            try:
                result = (self._supabase.table("findings")
                          .select("*")
                          .eq("case_id", case_id)
                          .order("created_at", desc=True)
                          .limit(1)
                          .execute())
                if result.data:
                    data = result.data[0]
                    if isinstance(data.get("findings"), str):
                        data["findings"] = json.loads(data["findings"])
                    return data
                return None
            except Exception as e:
                print(f"[DB] Supabase error in get_findings: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                records = self._local_query("findings", "case_id", case_id)
                if records:
                    r = records[-1]
                    if isinstance(r.get("findings"), str):
                        r["findings"] = json.loads(r["findings"])
                    return r
                return None
        else:
            records = self._local_query("findings", "case_id", case_id)
            if records:
                r = records[-1]
                if isinstance(r.get("findings"), str):
                    r["findings"] = json.loads(r["findings"])
                return r
            return None

    # === THREAT INTEL CACHE ===

    def cache_threat_intel(self, indicator: str, indicator_type: str, result: dict):
        """Cache a threat intel lookup result."""
        record = {
            "id": str(uuid.uuid4()),
            "indicator": indicator,
            "indicator_type": indicator_type,
            "result": json.dumps(result),
            "cached_at": datetime.now(timezone.utc).isoformat()
        }
        if self._supabase:
            try:
                self._supabase.table("threat_intel_cache").upsert(
                    record, on_conflict="indicator"
                ).execute()
            except Exception as e:
                print(f"[DB] Supabase error in cache_threat_intel: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                self._local_insert("threat_intel_cache", record)
        else:
            self._local_insert("threat_intel_cache", record)

    def get_cached_intel(self, indicator: str) -> Optional[dict]:
        """Get cached threat intel for an indicator."""
        if self._supabase:
            try:
                result = (self._supabase.table("threat_intel_cache")
                          .select("*")
                          .eq("indicator", indicator)
                          .execute())
                if result.data:
                    data = result.data[0]
                    data["result"] = json.loads(data["result"])
                    return data
                return None
            except Exception as e:
                print(f"[DB] Supabase error in get_cached_intel: {e}. Falling back to local storage.")
                self._supabase = None
                self._setup_local()
                records = self._local_query("threat_intel_cache", "indicator", indicator)
                if records:
                    r = records[-1]
                    if isinstance(r.get("result"), str):
                        r["result"] = json.loads(r["result"])
                    return r
                return None
        else:
            records = self._local_query("threat_intel_cache", "indicator", indicator)
            if records:
                r = records[-1]
                if isinstance(r.get("result"), str):
                    r["result"] = json.loads(r["result"])
                return r
            return None

    # === LOCAL STORAGE HELPERS ===

    def _local_insert(self, table: str, record: dict) -> dict:
        f = self._local_dir / f"{table}.json"
        data = json.loads(f.read_text())
        data.append(record)
        f.write_text(json.dumps(data, indent=2, default=str))
        return record

    def _local_update(self, table: str, record_id: str, updates: dict) -> dict:
        f = self._local_dir / f"{table}.json"
        data = json.loads(f.read_text())
        for item in data:
            if item.get("id") == record_id:
                item.update(updates)
                f.write_text(json.dumps(data, indent=2, default=str))
                return item
        return updates

    def _local_get(self, table: str, record_id: str) -> Optional[dict]:
        f = self._local_dir / f"{table}.json"
        data = json.loads(f.read_text())
        for item in data:
            if item.get("id") == record_id:
                return item
        return None

    def _local_list(self, table: str, limit: int) -> list:
        f = self._local_dir / f"{table}.json"
        data = json.loads(f.read_text())
        return sorted(data, key=lambda x: x.get("created_at", ""), reverse=True)[:limit]

    def _local_query(self, table: str, key: str, value: str) -> list:
        f = self._local_dir / f"{table}.json"
        data = json.loads(f.read_text())
        return [item for item in data if item.get(key) == value]


# Singleton
db = Database()
