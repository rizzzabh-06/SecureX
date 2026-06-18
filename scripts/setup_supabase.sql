-- =============================================================
-- SecureX — Supabase Schema
-- Run this in the Supabase SQL Editor (Dashboard → SQL Editor)
-- =============================================================

-- Cases table — stores each analysis case
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    apk_sha256 TEXT,
    apk_md5 TEXT,
    package_name TEXT DEFAULT '',
    size_bytes BIGINT DEFAULT 0,
    source TEXT DEFAULT 'file_upload',
    source_url TEXT,
    status TEXT DEFAULT 'pending',
    threat_score INTEGER DEFAULT 0,
    classification TEXT DEFAULT 'CLEAN',
    malware_family TEXT DEFAULT '',
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Findings table — stores full analysis results as JSON
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    findings JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Threat intel cache — avoid re-querying APIs
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id TEXT PRIMARY KEY,
    indicator TEXT UNIQUE NOT NULL,
    indicator_type TEXT NOT NULL,
    result JSONB NOT NULL,
    cached_at TIMESTAMPTZ DEFAULT NOW()
);

-- Custody chain entries
CREATE TABLE IF NOT EXISTS custody_chain (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    action TEXT NOT NULL,
    data JSONB,
    prev_hash TEXT,
    entry_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_intel_indicator ON threat_intel_cache(indicator);
CREATE INDEX IF NOT EXISTS idx_custody_case ON custody_chain(case_id);

-- Enable Row Level Security (optional for hackathon)
-- ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
