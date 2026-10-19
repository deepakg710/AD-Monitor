from __future__ import annotations
import math, os, json, pickle, logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
import numpy as np
from .db import now, dt, stamp, uid, js, obj, digest, settings, Database
from .normalize import canonical, scoped
from .rules import after_hours

LOG = logging.getLogger("admonitor.model")

FEATURE_SCHEMA_VERSION = 1
FEATURE_NAMES = [
    "total_events",
    "file_access_count",
    "distinct_sensitive_files",
    "denied_ratio",
    "after_hours_ratio",
    "distinct_paths",
    "device_novelty"
]

def c_factor(n: int) -> float:
    if n > 2:
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)
    if n == 2:
        return 1.0
    return 0.0

class IsolationTreeNode:
    def __init__(self, depth: int = 0, max_depth: int = 10):
        self.depth = depth
        self.max_depth = max_depth
        self.left: IsolationTreeNode | None = None
        self.right: IsolationTreeNode | None = None
        self.feature_idx: int | None = None
        self.split_val: float | None = None
        self.size: int = 0
        self.is_leaf: bool = True

    def fit(self, X: np.ndarray):
        self.size = len(X)
        if self.depth >= self.max_depth or self.size <= 1:
            self.is_leaf = True
            return

        mins = np.min(X, axis=0)
        maxs = np.max(X, axis=0)
        valid_features = np.where(maxs > mins)[0]
        if len(valid_features) == 0:
            self.is_leaf = True
            return

        self.feature_idx = int(np.random.choice(valid_features))
        f_min = float(mins[self.feature_idx])
        f_max = float(maxs[self.feature_idx])
        self.split_val = float(np.random.uniform(f_min, f_max))

        left_mask = X[:, self.feature_idx] < self.split_val
        self.left = IsolationTreeNode(self.depth + 1, self.max_depth)
        self.right = IsolationTreeNode(self.depth + 1, self.max_depth)
        self.left.fit(X[left_mask])
        self.right.fit(X[~left_mask])
        self.is_leaf = False

    def path_length(self, x: np.ndarray) -> float:
        if self.is_leaf or self.feature_idx is None:
            return self.depth + c_factor(self.size)
        if x[self.feature_idx] < self.split_val:
            return self.left.path_length(x)
        else:
            return self.right.path_length(x)

class LightweightIsolationForest:
    def __init__(self, n_estimators: int = 100, max_samples: int = 256, contamination: float = 0.05, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.trees: list[IsolationTreeNode] = []
        self.sub_sample_size: int = 256
        self.threshold: float = 0.60
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray):
        if len(X) == 0:
            raise ValueError("Cannot fit model on empty dataset")
        np.random.seed(self.random_state)
        n_samples = len(X)
        self.sub_sample_size = min(self.max_samples, n_samples)
        max_depth = math.ceil(math.log2(max(self.sub_sample_size, 2)))
        self.trees = []
        for _ in range(self.n_estimators):
            idx = np.random.choice(n_samples, self.sub_sample_size, replace=False) if n_samples > self.sub_sample_size else np.arange(n_samples)
            tree = IsolationTreeNode(depth=0, max_depth=max_depth)
            tree.fit(X[idx])
            self.trees.append(tree)

        scores = self.score_samples(X)
        self.threshold = float(np.percentile(scores, 100.0 * (1.0 - self.contamination)))
        # Safeguard threshold bounds
        self.threshold = max(0.55, min(self.threshold, 0.90))
        self.is_fitted = True

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        c_n = c_factor(self.sub_sample_size)
        if c_n <= 0:
            return np.full(len(X), 0.5)
        scores = []
        for x in X:
            avg_path = float(np.mean([t.path_length(x) for t in self.trees]))
            score = 2.0 ** (- (avg_path / c_n))
            scores.append(score)
        return np.array(scores)

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.score_samples(X)
        return (scores >= self.threshold).astype(int)

def extract_window_features(c, user_sid: str, start_time: str, end_time: str, policy: dict) -> tuple[dict, list[str]]:
    """Extracts a vector of behavioral features from stored events for a user in a given time window."""
    rows = c.execute(
        "SELECT id, time, category, result, canonical_path, access_device_id, device_id "
        "FROM events WHERE user_sid = ? AND time >= ? AND time < ? ORDER BY time",
        (user_sid, start_time, end_time)
    ).fetchall()

    evidence_ids = [r["id"] for r in rows]
    total_events = len(rows)
    if total_events == 0:
        return {
            "total_events": 0,
            "file_access_count": 0,
            "distinct_sensitive_files": 0,
            "denied_ratio": 0.0,
            "after_hours_ratio": 0.0,
            "distinct_paths": 0,
            "device_novelty": 0
        }, []

    file_events = [r for r in rows if r["category"] in ("file_read", "file_write", "file_access", "file_copy")]
    sensitive_roots = policy.get("sensitive_paths", [])
    sensitive_files = {r["canonical_path"] for r in rows if scoped(r["canonical_path"], sensitive_roots)}
    denied_events = [r for r in rows if r["result"] == "denied"]
    after_hours_events = [r for r in rows if after_hours(r["time"], policy)]
    distinct_paths = {r["canonical_path"] for r in rows if r["canonical_path"]}

    # Check device novelty: is access_device_id known primary or associated prior to this window?
    primary_devices = {r["device_id"] for r in c.execute("SELECT device_id FROM associations WHERE employee_sid = ? AND is_primary = 1", (user_sid,)).fetchall()}
    device_novelty = 0
    if primary_devices:
        for r in rows:
            dev = r["access_device_id"] or r["device_id"]
            if dev and dev not in primary_devices:
                device_novelty = 1
                break

    values = {
        "total_events": total_events,
        "file_access_count": len(file_events),
        "distinct_sensitive_files": len(sensitive_files),
        "denied_ratio": round(len(denied_events) / total_events, 4),
        "after_hours_ratio": round(len(after_hours_events) / total_events, 4),
        "distinct_paths": len(distinct_paths),
        "device_novelty": device_novelty
    }
    return values, evidence_ids

def get_user_baseline(c, user_sid: str) -> dict:
    """Returns baseline stats for a user if minimum history is met, else indicates cold start."""
    s = settings(c)
    min_windows = s.get("model_user_min_windows", 24)
    rows = c.execute(
        "SELECT values_json FROM features WHERE user_sid = ? AND schema_version = ? ORDER BY start_time",
        (user_sid, FEATURE_SCHEMA_VERSION)
    ).fetchall()

    if len(rows) < min_windows:
        return {
            "status": "Collecting baseline",
            "samples_collected": len(rows),
            "samples_required": min_windows,
            "is_ready": False,
            "medians": {},
            "iqrs": {}
        }

    data = [obj(r["values_json"]) for r in rows]
    medians = {}
    iqrs = {}
    for name in FEATURE_NAMES:
        vals = [d[name] for d in data]
        med = float(np.median(vals))
        q75, q25 = np.percentile(vals, [75, 25])
        iqr = float(q75 - q25)
        medians[name] = round(med, 3)
        iqrs[name] = round(max(iqr, 0.001), 3)

    return {
        "status": "Trained baseline",
        "samples_collected": len(rows),
        "samples_required": min_windows,
        "is_ready": True,
        "medians": medians,
        "iqrs": iqrs
    }

def explain_anomaly(observed: dict, baseline: dict, score: float, threshold: float) -> str:
    medians = baseline.get("medians", {})
    iqrs = baseline.get("iqrs", {})
    deviations = []
    for name in FEATURE_NAMES:
        obs = observed.get(name, 0)
        med = medians.get(name, 0.0)
        iqr = iqrs.get(name, 1.0)
        z = (obs - med) / max(iqr, 0.01)
        if z >= 2.0 and obs > med:
            human_name = name.replace("_", " ")
            deviations.append(f"unusually high {human_name} ({obs} vs baseline median {med})")

    if not deviations:
        reason = "multivariate anomaly combination across activity frequency and timing"
    else:
        reason = ", ".join(deviations[:3])

    return (
        f"AI behavior anomaly score: {score:.3f} (threshold {threshold:.3f}). "
        f"Observed pattern showed {reason}. "
        f"Baseline source: {baseline.get('status', 'User profile')} ({baseline.get('samples_collected', 0)} samples). "
        f"An anomaly score indicates statistical divergence from baseline, not proof of malicious intent."
    )

def train_and_persist_model(db: Database) -> dict:
    """Trains the Isolation Forest model on historical feature windows and activates it."""
    with db.tx() as c:
        s = settings(c)
        rows = c.execute(
            "SELECT id, user_sid, values_json FROM features WHERE schema_version = ? ORDER BY start_time",
            (FEATURE_SCHEMA_VERSION,)
        ).fetchall()

        if len(rows) < s.get("model_min_windows", 48):
            return {
                "success": False,
                "reason": f"Insufficient training windows: {len(rows)} available, {s.get('model_min_windows', 48)} required. Status: Collecting baseline."
            }

        X = []
        feature_ids = []
        for r in rows:
            v = obj(r["values_json"])
            vec = [v.get(name, 0.0) for name in FEATURE_NAMES]
            X.append(vec)
            feature_ids.append(r["id"])

        X_mat = np.array(X, dtype=float)
        contamination = float(s.get("model_contamination", 0.05))
        model = LightweightIsolationForest(n_estimators=100, max_samples=256, contamination=contamination, random_state=42)
        model.fit(X_mat)

        model_id = uid()
        storage_dir = Path(__file__).parent / "data" / "models"
        storage_dir.mkdir(parents=True, exist_ok=True)
        model_file = storage_dir / f"{model_id}.pkl"

        data_bytes = pickle.dumps(model)
        model_file.write_bytes(data_bytes)
        file_sha256 = digest(data_bytes.hex())

        metadata = {
            "model_type": "IsolationForest_CPU",
            "feature_names": FEATURE_NAMES,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "samples_trained": len(X),
            "threshold": model.threshold,
            "contamination": contamination,
            "trained_at": now(),
            "provenance": "Calculated on stored lab feature windows"
        }

        # Deactivate older models
        c.execute("UPDATE models SET active = 0")
        c.execute(
            "INSERT INTO models(id, created_at, active, metadata, path, sha256) VALUES(?, ?, 1, ?, ?, ?)",
            (model_id, now(), js(metadata), str(model_file), file_sha256)
        )

        # Score historical features and populate model_scores
        scores = model.score_samples(X_mat)
        for fid, score, r, vec_dict in zip(feature_ids, scores, rows, [obj(r["values_json"]) for r in rows]):
            base = get_user_baseline(c, r["user_sid"])
            expl = explain_anomaly(vec_dict, base, float(score), model.threshold) if score >= model.threshold else "Within expected baseline bounds"
            c.execute(
                "INSERT INTO model_scores(model_id, feature_id, score, baseline_kind, explanation) "
                "VALUES(?, ?, ?, ?, ?) ON CONFLICT(model_id, feature_id) DO UPDATE SET score = excluded.score, explanation = excluded.explanation",
                (model_id, fid, float(score), base["status"], expl)
            )

        return {
            "success": True,
            "model_id": model_id,
            "samples_trained": len(X),
            "threshold": round(model.threshold, 4),
            "created_at": now()
        }
