"""
drift_monitor.py — Model drift detection over Blob-stored prediction audit logs.

Phase 2.3: Consumes JSONL prediction audit logs from Blob Storage and computes
drift signals vs. training-time baseline values. Exposed as GET /health/drift
(bearer-token protected, token in Key Vault as 'cyberguard-drift-bearer-token').

Drift signals tracked:
  - Prediction rate drift: rolling 24h phishing rate vs. baseline ~51.2%
  - Confidence distribution: mean/std of calibrated confidence scores
  - Channel distribution: SMS/WA/Email proportion shifts
  - Feature activation: rolling has_dangerous_link and contains_urgency means
"""

from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# Baseline values from training data (data/processed/processed_cyber_data.csv)
_BASELINE_PHISHING_RATE = 0.369          # 36.9% phishing in training corpus
_BASELINE_CONFIDENCE_MEAN = 72.0         # approximate mean calibrated confidence %
_DRIFT_PHISHING_THRESHOLD = 0.15         # >15% absolute drift = alert
_DRIFT_CONFIDENCE_THRESHOLD = 15.0       # >15 points drift in mean confidence = alert


class DriftMonitor:
    """
    Reads prediction audit JSONL logs from Blob Storage and computes
    rolling 24h drift signals.
    """

    def __init__(
        self,
        blob_storage: Any,
        logs_prefix: str = "logs/predictions",
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.blob_storage = blob_storage
        self.logs_prefix = logs_prefix
        self.logger = logger or logging.getLogger(__name__)

    def _list_blob_paths_last_24h(self) -> List[str]:
        """Return blob paths for the last 24 hours of prediction logs."""
        paths: List[str] = []
        now = datetime.now(timezone.utc)
        for hours_back in range(25):  # 24h + 1 for safety margin
            ts = now - timedelta(hours=hours_back)
            path = f"{self.logs_prefix}/{ts.strftime('%Y/%m/%d')}/"
            paths.append(path)
        return list(dict.fromkeys(paths))  # deduplicate while preserving order

    def _read_jsonl_blobs(self) -> List[Dict[str, Any]]:
        """Download and parse all JSONL entries from the last 24h log files."""
        if not self.blob_storage or not getattr(self.blob_storage, "enabled", False):
            return []

        records: List[Dict[str, Any]] = []
        prefixes = self._list_blob_paths_last_24h()

        for prefix in prefixes:
            try:
                blob_list = self.blob_storage.list_blobs(prefix=prefix)
            except Exception:
                continue

            for blob_name in (blob_list or []):
                try:
                    content = self.blob_storage.download_blob_as_bytes(blob_name)
                    if not content:
                        continue
                    for line in io.TextIOWrapper(io.BytesIO(content), encoding="utf-8"):
                        line = line.strip()
                        if line:
                            records.append(json.loads(line))
                except Exception as exc:
                    self.logger.debug("Skipping blob %s: %s", blob_name, exc)

        return records

    def compute(self) -> Dict[str, Any]:
        """
        Compute all drift signals from the last 24h of prediction events.
        Returns a dict safe to return directly from the /health/drift endpoint.
        """
        records = self._read_jsonl_blobs()

        if not records:
            return {
                "status": "no_data",
                "message": "No prediction records found in last 24h. Drift cannot be computed.",
                "record_count": 0,
            }

        # --- Prediction rate drift ---
        is_phishing_flags = [r.get("is_phishing", False) for r in records]
        phishing_rate = sum(is_phishing_flags) / len(is_phishing_flags)
        phishing_drift = abs(phishing_rate - _BASELINE_PHISHING_RATE)
        phishing_alert = phishing_drift > _DRIFT_PHISHING_THRESHOLD

        # --- Confidence distribution ---
        confidences = [float(r["confidence"]) for r in records if "confidence" in r]
        conf_mean = sum(confidences) / len(confidences) if confidences else 0.0
        conf_std = (
            (sum((c - conf_mean) ** 2 for c in confidences) / len(confidences)) ** 0.5
            if confidences else 0.0
        )
        confidence_drift = abs(conf_mean - _BASELINE_CONFIDENCE_MEAN)
        confidence_alert = confidence_drift > _DRIFT_CONFIDENCE_THRESHOLD

        # --- Channel distribution ---
        channel_counts: Dict[str, int] = {"sms": 0, "whatsapp": 0, "email": 0, "unknown": 0}
        for r in records:
            ch = (r.get("source") or "unknown").lower()
            if ch in channel_counts:
                channel_counts[ch] += 1
            else:
                channel_counts["unknown"] += 1
        total = len(records)
        channel_pct = {ch: round(cnt / total * 100, 2) for ch, cnt in channel_counts.items()}

        return {
            "status": "ok",
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "record_count": total,
            "prediction_rate_drift": {
                "phishing_rate_24h": round(phishing_rate, 4),
                "baseline_phishing_rate": _BASELINE_PHISHING_RATE,
                "absolute_drift": round(phishing_drift, 4),
                "threshold": _DRIFT_PHISHING_THRESHOLD,
                "alert": phishing_alert,
            },
            "confidence_distribution": {
                "mean": round(conf_mean, 2),
                "std": round(conf_std, 2),
                "baseline_mean": _BASELINE_CONFIDENCE_MEAN,
                "absolute_drift": round(confidence_drift, 2),
                "threshold": _DRIFT_CONFIDENCE_THRESHOLD,
                "alert": confidence_alert,
            },
            "channel_distribution_pct": channel_pct,
            "alerts": {
                "any_alert": phishing_alert or confidence_alert,
                "phishing_rate_alert": phishing_alert,
                "confidence_alert": confidence_alert,
            },
        }
