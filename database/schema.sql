-- PHISH GUARD - Hybrid AI Security System Database Schema
-- Defines relational tables for Users, Scan History, Blacklist, Reports, Model Metrics, Threat Heatmap, and Settings.

-- 1. Users Table (for Admin authentication & auditing)
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. ScanHistory Table (logs multi-modal scans from browser extension & API)
CREATE TABLE IF NOT EXISTS ScanHistory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    html_hash TEXT DEFAULT '',
    prediction TEXT NOT NULL,          -- 'SAFE', 'SUSPICIOUS', 'PHISHING'
    confidence REAL NOT NULL,          -- 0.0 to 100.0 percent
    risk_level TEXT NOT NULL,          -- 'Low', 'Medium', 'High', 'Critical'
    hybrid_score REAL DEFAULT 0.0,     -- Multi-layer weighted score (0-100)
    layer_scores_json TEXT,            -- JSON breakdown of each layer's score
    scan_time_ms REAL NOT NULL,        -- Execution duration in milliseconds
    reasons TEXT,                      -- JSON array of human-readable detection reasons
    features_json TEXT,                -- Full JSON payload of extracted features
    screenshot_path TEXT,              -- Relative path to captured screenshot
    user_feedback TEXT DEFAULT '',     -- Optional user feedback tag
    client_ip TEXT DEFAULT '127.0.0.1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON ScanHistory(domain);
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON ScanHistory(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_history_prediction ON ScanHistory(prediction);

-- 3. Blacklist Table (explicit domain or regex patterns blocked instantly)
CREATE TABLE IF NOT EXISTS Blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT UNIQUE NOT NULL,      -- Domain or URL pattern (e.g. evil-phish.xyz)
    domain TEXT NOT NULL,
    reason TEXT NOT NULL,
    added_by TEXT DEFAULT 'system',
    is_active INTEGER DEFAULT 1,       -- 1 = active, 0 = disabled
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blacklist_domain ON Blacklist(domain);

-- 4. Reports Table (user feedback for false positives and false negatives)
CREATE TABLE IF NOT EXISTS Reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    user_feedback TEXT NOT NULL,       -- 'false_positive' or 'false_negative'
    reported_type TEXT,                -- What user believed it was (e.g. 'Safe' or 'Phishing')
    actual_status TEXT,                -- What Phish Guard classified it as
    comments TEXT,
    status TEXT DEFAULT 'pending',     -- 'pending', 'reviewed', 'resolved'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. ModelMetrics Table (persisted evaluation benchmarks for all ML models)
CREATE TABLE IF NOT EXISTS ModelMetrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    accuracy REAL NOT NULL,
    precision_score REAL NOT NULL,
    recall REAL NOT NULL,
    f1 REAL NOT NULL,
    roc_auc REAL NOT NULL,
    training_time REAL NOT NULL,
    is_active INTEGER DEFAULT 0,       -- 1 if active champion
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. ThreatHeatmap Table (aggregates attack vectors and target brands)
CREATE TABLE IF NOT EXISTS ThreatHeatmap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_brand TEXT NOT NULL,
    attack_vector TEXT NOT NULL,       -- 'Credential Harvesting', 'Brand Impersonation', 'Fake Payment', 'Scareware'
    threat_level TEXT NOT NULL,        -- 'High', 'Critical'
    hit_count INTEGER DEFAULT 1,
    last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Settings Table (dynamic configuration thresholds and flags)
CREATE TABLE IF NOT EXISTS Settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
