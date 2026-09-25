-- PostgreSQL relational design for the project

CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    scan_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    target_url TEXT NOT NULL,
    scan_type VARCHAR(30) DEFAULT 'Full',
    crawl_depth INTEGER DEFAULT 1,
    scan_speed VARCHAR(20) DEFAULT 'Balanced',
    scan_status VARCHAR(30) DEFAULT 'Pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE TABLE vulnerabilities (
    vulnerability_id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(scan_id) ON DELETE CASCADE,
    type VARCHAR(120) NOT NULL,
    url TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    owasp_category VARCHAR(120),
    description TEXT,
    evidence TEXT
);

CREATE TABLE ai_analysis (
    analysis_id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    risk_score DECIMAL(5,2),
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reports (
    report_id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(scan_id) ON DELETE CASCADE,
    report_type VARCHAR(20),
    file_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
