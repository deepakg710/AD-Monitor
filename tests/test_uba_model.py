import tempfile
import numpy as np
from pathlib import Path
from backend.db import Database, now, js, uid
from backend.model import (
    LightweightIsolationForest, extract_window_features,
    get_user_baseline, explain_anomaly, train_and_persist_model,
    FEATURE_NAMES, FEATURE_SCHEMA_VERSION
)

def test_isolation_forest_anomaly_detection():
    np.random.seed(42)
    # 100 normal activity samples
    normal_data = np.random.normal(loc=10.0, scale=2.0, size=(100, len(FEATURE_NAMES)))
    # 5 extreme anomalous spike samples
    anom_data = np.random.normal(loc=100.0, scale=5.0, size=(5, len(FEATURE_NAMES)))
    all_data = np.vstack([normal_data, anom_data])

    model = LightweightIsolationForest(n_estimators=50, random_state=42)
    model.fit(all_data)

    normal_scores = model.score_samples(normal_data[:5])
    anom_scores = model.score_samples(anom_data)

    # Anomaly scores should be substantially higher than normal scores
    assert np.mean(anom_scores) > np.mean(normal_scores)
    # Most anomalies should be flagged
    preds = model.predict(anom_data)
    assert np.sum(preds) >= 3

def test_cold_start_and_baseline():
    with tempfile.TemporaryDirectory() as td:
        db = Database(Path(td) / "test.db")
        db.migrate()

        with db.tx() as c:
            # Check baseline for user with 0 samples
            b_zero = get_user_baseline(c, "S-1-5-NEW-USER")
            assert b_zero["status"] == "Collecting baseline"
            assert b_zero["is_ready"] is False
            assert b_zero["samples_collected"] == 0

            # Insert 25 feature windows for a user
            for i in range(25):
                f_vals = {
                    "total_events": 15 + i % 5,
                    "file_access_count": 8,
                    "distinct_sensitive_files": 1,
                    "denied_ratio": 0.0,
                    "after_hours_ratio": 0.0,
                    "distinct_paths": 5,
                    "device_novelty": 0
                }
                c.execute(
                    "INSERT INTO features(id, user_sid, start_time, end_time, schema_version, values_json, evidence_ids, provenance) "
                    "VALUES(?, ?, ?, ?, ?, ?, '[]', 'test')",
                    (uid(), "S-1-5-SALES-USER", f"2026-10-0{i+1}T08:00:00Z", f"2026-10-0{i+1}T12:00:00Z", FEATURE_SCHEMA_VERSION, js(f_vals))
                )

            # Check baseline now
            b_ready = get_user_baseline(c, "S-1-5-SALES-USER")
            assert b_ready["status"] == "Trained baseline"
            assert b_ready["is_ready"] is True
            assert b_ready["samples_collected"] == 25
            assert "total_events" in b_ready["medians"]

def test_explain_anomaly_format():
    baseline = {
        "status": "Trained baseline",
        "samples_collected": 30,
        "medians": {"distinct_sensitive_files": 0.0, "after_hours_ratio": 0.0},
        "iqrs": {"distinct_sensitive_files": 1.0, "after_hours_ratio": 0.1}
    }
    observed = {
        "distinct_sensitive_files": 8,
        "after_hours_ratio": 0.90
    }
    explanation = explain_anomaly(observed, baseline, 0.78, 0.60)
    assert "0.78" in explanation
    assert "distinct sensitive files" in explanation
    assert "statistical divergence" in explanation
