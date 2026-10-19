CREATE TABLE jobs(id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, result TEXT, error TEXT);
