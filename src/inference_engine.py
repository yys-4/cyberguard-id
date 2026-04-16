import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

try:
    import shap
except Exception:  # pragma: no cover - fallback handled in runtime
    shap = None


SLANG_DICT = {
    "sgera": "segera",
    "mw": "mau",
    "sldo": "saldo",
    "krna": "karena",
    "blm": "belum",
    "klo": "kalau",
    "yg": "yang",
    "dgn": "dengan",
    "utk": "untuk",
    "bs": "bisa",
    "udh": "sudah",
    "bner": "benar",
    "ga": "tidak",
    "gak": "tidak",
    "tp": "tapi",
    "almt": "alamat",
    "krng": "kurang",
    "dsni": "disini",
    "mhn": "mohon",
    "mksihh": "terima kasih",
    "yach": "ya",
    "temen2": "teman-teman",
    "teman2": "teman-teman",
    "bnyk": "banyak",
    "d": "di",
    "dr": "dari",
    "kmi": "kami",
    "kmbali": "kembali",
    "tnpa": "tanpa",
    "kntor": "kantor",
    "prgkat": "perangkat",
    "smntara": "sementara",
}

DANGEROUS_PATTERNS = re.compile(
    r"(\.apk|\.top|\.xyz|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|s\.id|bit\.ly|tinyurl)",
    flags=re.IGNORECASE,
)
URGENCY_PATTERN = re.compile(
    r"(dibekukan|blokir|pajak|hadiah|segera|tutup|hangus|peringatan|terlambat|denda|terpotong)",
    flags=re.IGNORECASE,
)

KNOWN_CHANNELS = ("sms", "whatsapp", "email")


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _parse_float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = float(raw)
    except ValueError:
        return default

    return max(minimum, min(maximum, value))


def _parse_int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default

    try:
        value = int(raw)
    except ValueError:
        return default

    return max(minimum, min(maximum, value))


def _clip_probability(value: float) -> float:
    return max(1e-6, min(1.0 - 1e-6, float(value)))


def normalize_channel(source: Optional[str]) -> str:
    if source is None:
        return "unknown"

    raw = str(source).strip().lower()
    if not raw:
        return "unknown"

    compact = re.sub(r"[\s_\-]+", "", raw)

    if compact in {"sms", "text", "textmessage"} or "sms" in compact:
        return "sms"
    if compact in {"wa", "wame", "whatsapp", "whatsap", "whatsapps", "whatsappchat"} or "whatsapp" in compact:
        return "whatsapp"
    if compact in {"email", "mail", "e-mail"} or "email" in compact or compact.endswith("mail"):
        return "email"

    return "unknown"


class ThresholdPolicy:
    SUPPORTED = {"low", "balanced", "high"}

    def __init__(
        self,
        default_sensitivity: str,
        thresholds: Dict[str, float],
        uncertainty_margin: float,
        auto_channel_sensitivity: Dict[str, str],
        channel_offsets: Dict[str, float],
    ):
        self.default_sensitivity = self._normalize(default_sensitivity)
        self.thresholds = thresholds
        self.uncertainty_margin = uncertainty_margin
        self.auto_channel_sensitivity = {
            channel: self._normalize(level) for channel, level in auto_channel_sensitivity.items()
        }
        self.channel_offsets = channel_offsets

    @classmethod
    def from_env(cls) -> "ThresholdPolicy":
        thresholds = {
            "low": _parse_float_env("THRESHOLD_LOW", 0.75, 0.01, 0.99),
            "balanced": _parse_float_env("THRESHOLD_BALANCED", 0.60, 0.01, 0.99),
            "high": _parse_float_env("THRESHOLD_HIGH", 0.45, 0.01, 0.99),
        }

        auto_channel_sensitivity = {
            "sms": os.getenv("AUTO_SENSITIVITY_SMS", "low"),
            "whatsapp": os.getenv("AUTO_SENSITIVITY_WHATSAPP", "balanced"),
            "email": os.getenv("AUTO_SENSITIVITY_EMAIL", "balanced"),
        }

        channel_offsets = {
            "sms": _parse_float_env("THRESHOLD_OFFSET_SMS", 0.0, -0.25, 0.25),
            "whatsapp": _parse_float_env("THRESHOLD_OFFSET_WHATSAPP", 0.0, -0.25, 0.25),
            "email": _parse_float_env("THRESHOLD_OFFSET_EMAIL", 0.0, -0.25, 0.25),
        }

        return cls(
            default_sensitivity=os.getenv("DEFAULT_SENSITIVITY", "balanced"),
            thresholds=thresholds,
            uncertainty_margin=_parse_float_env("THRESHOLD_UNCERTAINTY_MARGIN", 0.05, 0.0, 0.25),
            auto_channel_sensitivity=auto_channel_sensitivity,
            channel_offsets=channel_offsets,
        )

    def _normalize(self, sensitivity: str) -> str:
        value = (sensitivity or "").strip().lower()
        if value not in self.SUPPORTED:
            return "balanced"
        return value

    def resolve(self, sensitivity: Optional[str], channel: str) -> Dict[str, Any]:
        channel_key = normalize_channel(channel)
        user_input = (sensitivity or "").strip().lower()

        if user_input in {"", "auto", "channel", "default"}:
            selected = self.auto_channel_sensitivity.get(channel_key, self.default_sensitivity)
            mode = "auto_channel"
        else:
            selected = self._normalize(user_input)
            mode = "user_override"

        base_threshold = self.thresholds[selected]
        channel_offset = self.channel_offsets.get(channel_key, 0.0)
        decision_threshold = max(0.01, min(0.99, base_threshold + channel_offset))

        return {
            "sensitivity": selected,
            "mode": mode,
            "channel": channel_key,
            "base_threshold": base_threshold,
            "channel_offset": channel_offset,
            "decision_threshold": decision_threshold,
        }

    def get_config(self) -> Dict[str, Any]:
        return {
            "default_sensitivity": self.default_sensitivity,
            "thresholds": {key: round(value * 100.0, 2) for key, value in self.thresholds.items()},
            "uncertainty_margin": round(self.uncertainty_margin * 100.0, 2),
            "auto_channel_sensitivity": self.auto_channel_sensitivity,
            "channel_offsets": {key: round(value * 100.0, 2) for key, value in self.channel_offsets.items()},
        }


class ChannelSegmentProfiler:
    def __init__(self, data_path: str, logger: logging.Logger):
        self.data_path = data_path
        self.logger = logger

        self.global_prior = 0.5
        self.channel_profiles = {
            "sms": self._default_profile(mean_tokens=16.0, std_tokens=8.0, link_rate=0.15, urgency_rate=0.18),
            "whatsapp": self._default_profile(mean_tokens=28.0, std_tokens=12.0, link_rate=0.22, urgency_rate=0.20),
            "email": self._default_profile(mean_tokens=36.0, std_tokens=16.0, link_rate=0.25, urgency_rate=0.22),
        }

        self._load_profiles()

    def _default_profile(
        self,
        mean_tokens: float,
        std_tokens: float,
        link_rate: float,
        urgency_rate: float,
    ) -> Dict[str, Any]:
        return {
            "sample_size": 0,
            "prior_phishing": 0.5,
            "mean_tokens": mean_tokens,
            "std_tokens": max(1.0, std_tokens),
            "link_rate": link_rate,
            "urgency_rate": urgency_rate,
        }

    def _token_count(self, text: str) -> int:
        if not isinstance(text, str) or not text.strip():
            return 0
        return len(text.split())

    def _load_profiles(self) -> None:
        if not os.path.exists(self.data_path):
            self.logger.warning("Channel profiler data not found at %s. Using default channel profiles.", self.data_path)
            return

        try:
            df = pd.read_csv(self.data_path)
        except Exception as exc:  # pragma: no cover - environment dependent
            self.logger.warning("Failed to load channel profiler data: %s", exc)
            return

        if "processed_text" not in df.columns:
            self.logger.warning("Channel profiler requires processed_text column. Using defaults.")
            return

        df = df.copy()
        df["processed_text"] = df["processed_text"].fillna("").astype(str)

        if "label" in df.columns and not df["label"].dropna().empty:
            self.global_prior = _clip_probability(float(df["label"].fillna(0).astype(float).mean()))

        if "platform" not in df.columns:
            self.logger.warning("Channel profiler requires platform column for segmentation. Using defaults.")
            return

        df["channel"] = df["platform"].apply(normalize_channel)

        if "has_dangerous_link" not in df.columns:
            df["has_dangerous_link"] = df["processed_text"].str.contains(DANGEROUS_PATTERNS, regex=True).astype(int)
        if "contains_urgency" not in df.columns:
            df["contains_urgency"] = df["processed_text"].str.contains(URGENCY_PATTERN, regex=True).astype(int)

        for channel in KNOWN_CHANNELS:
            channel_df = df[df["channel"] == channel]
            if channel_df.empty:
                continue

            token_counts = channel_df["processed_text"].apply(self._token_count).astype(float)
            mean_tokens = float(token_counts.mean()) if not token_counts.empty else self.channel_profiles[channel]["mean_tokens"]
            std_tokens = float(token_counts.std(ddof=0)) if not token_counts.empty else self.channel_profiles[channel]["std_tokens"]
            std_tokens = max(1.0, std_tokens)

            if "label" in channel_df.columns and not channel_df["label"].dropna().empty:
                prior_phishing = _clip_probability(float(channel_df["label"].fillna(0).astype(float).mean()))
            else:
                prior_phishing = self.global_prior

            link_rate = _clip_probability(float(channel_df["has_dangerous_link"].fillna(0).astype(float).mean()))
            urgency_rate = _clip_probability(float(channel_df["contains_urgency"].fillna(0).astype(float).mean()))

            self.channel_profiles[channel] = {
                "sample_size": int(len(channel_df)),
                "prior_phishing": prior_phishing,
                "mean_tokens": mean_tokens,
                "std_tokens": std_tokens,
                "link_rate": link_rate,
                "urgency_rate": urgency_rate,
            }

    def get_profile(self, channel: str) -> Dict[str, Any]:
        channel_key = normalize_channel(channel)
        return self.channel_profiles.get(channel_key, self._default_profile(24.0, 10.0, 0.2, 0.2))

    def adjust_probability(
        self,
        probability: float,
        channel: str,
        weight: float = 1.0,
        min_sample: int = 200,
        smoothing: float = 200.0,
        max_odds_ratio: float = 3.0,
    ) -> Tuple[float, Dict[str, Any]]:
        channel_key = normalize_channel(channel)
        profile = self.get_profile(channel_key)
        bounded_probability = _clip_probability(probability)

        metadata = {
            "applied": False,
            "channel": channel_key,
            "global_prior": round(self.global_prior * 100.0, 2),
            "channel_prior": round(profile["prior_phishing"] * 100.0, 2),
            "odds_ratio": 1.0,
            "weight": weight,
            "sample_size": profile["sample_size"],
            "min_sample": min_sample,
            "smoothing": round(float(smoothing), 2),
            "smoothed_channel_prior": round(profile["prior_phishing"] * 100.0, 2),
        }

        if channel_key not in KNOWN_CHANNELS or profile["sample_size"] < max(1, min_sample) or weight <= 0.0:
            return bounded_probability, metadata

        global_odds = self.global_prior / (1.0 - self.global_prior)
        if smoothing > 0.0:
            smoothed_channel_prior = (
                profile["prior_phishing"] * profile["sample_size"] + self.global_prior * smoothing
            ) / (profile["sample_size"] + smoothing)
        else:
            smoothed_channel_prior = profile["prior_phishing"]

        smoothed_channel_prior = _clip_probability(smoothed_channel_prior)
        channel_odds = smoothed_channel_prior / (1.0 - smoothed_channel_prior)

        raw_prior_odds_ratio = channel_odds / global_odds
        capped_prior_odds_ratio = max(1.0 / max_odds_ratio, min(max_odds_ratio, raw_prior_odds_ratio))
        weighted_ratio = capped_prior_odds_ratio ** weight

        raw_odds = bounded_probability / (1.0 - bounded_probability)
        adjusted_odds = raw_odds * weighted_ratio
        adjusted_probability = _clip_probability(adjusted_odds / (1.0 + adjusted_odds))

        metadata["applied"] = True
        metadata["odds_ratio"] = round(weighted_ratio, 6)
        metadata["smoothed_channel_prior"] = round(smoothed_channel_prior * 100.0, 2)
        return adjusted_probability, metadata

    def build_channel_context(
        self,
        channel: str,
        processed_text: str,
        features_payload: Dict[str, List[Any]],
    ) -> Tuple[List[str], Dict[str, Any]]:
        channel_key = normalize_channel(channel)
        profile = self.get_profile(channel_key)

        token_count = self._token_count(processed_text)
        mean_tokens = float(profile["mean_tokens"])
        std_tokens = max(1.0, float(profile["std_tokens"]))
        token_z_score = (token_count - mean_tokens) / std_tokens

        has_link = bool(features_payload["has_dangerous_link"][0])
        has_urgency = bool(features_payload["contains_urgency"][0])

        contextual_reasoning: List[str] = []

        if channel_key == "sms":
            if has_link:
                if profile["link_rate"] <= 0.35:
                    contextual_reasoning.append(
                        f"Link ini sangat tidak lazim ditemukan di protokol SMS (baseline {profile['link_rate'] * 100:.1f}%)."
                    )
                else:
                    contextual_reasoning.append(
                        "Link pada kanal SMS tetap perlu verifikasi ekstra karena SMS normal umumnya ringkas dan minim tautan."
                    )
            if token_z_score >= 1.2:
                contextual_reasoning.append(
                    "Struktur pesan lebih naratif dari pola SMS normal dan menyerupai gaya percakapan WhatsApp."
                )

        elif channel_key == "whatsapp":
            if has_link and token_z_score <= -1.0:
                contextual_reasoning.append(
                    "Pesan WhatsApp ini jauh lebih singkat dari pola naratif normal dan langsung membawa link."
                )
            if has_urgency and profile["urgency_rate"] <= 0.35:
                contextual_reasoning.append(
                    "Bahasa desakan pada WhatsApp ini berada di atas pola baseline kanal."
                )

        elif channel_key == "email":
            if has_urgency:
                contextual_reasoning.append(
                    "Desakan cepat pada kanal email merupakan red flag yang sering dipakai pada kampanye phishing."
                )
            if has_link and profile["link_rate"] <= 0.45:
                contextual_reasoning.append(
                    "Kerapatan tautan pada email ini lebih agresif dibanding pola normal kanal."
                )

        if not contextual_reasoning and channel_key in KNOWN_CHANNELS:
            contextual_reasoning.append(
                f"Penilaian juga mempertimbangkan distribusi kata khas kanal {channel_key.upper()} untuk konteks keputusan."
            )

        analysis = {
            "channel": channel_key,
            "token_count": token_count,
            "expected_token_mean": round(mean_tokens, 2),
            "expected_token_std": round(std_tokens, 2),
            "token_z_score": round(float(token_z_score), 4),
            "baseline_link_rate": round(float(profile["link_rate"]) * 100.0, 2),
            "baseline_urgency_rate": round(float(profile["urgency_rate"]) * 100.0, 2),
            "channel_sample_size": int(profile["sample_size"]),
        }

        return contextual_reasoning, analysis


def normalize_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    words = text.split()
    return " ".join([SLANG_DICT.get(word.lower(), word) for word in words])


def clean_and_tokenize(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9\s!]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    tokens = re.findall(r"\b\w+\b|!", text)
    return " ".join(tokens)


def extract_inference_features(text: str) -> Dict[str, List[Any]]:
    text_norm = normalize_text(text)
    has_dangerous_link = int(bool(DANGEROUS_PATTERNS.search(text_norm)))
    contains_urgency = int(bool(URGENCY_PATTERN.search(text_norm)))
    processed_text = clean_and_tokenize(text_norm)

    return {
        "processed_text": [processed_text],
        "has_dangerous_link": [has_dangerous_link],
        "contains_urgency": [contains_urgency],
    }


class HybridThreatAnalyzer:
    def __init__(self, model_path: str, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.model = joblib.load(model_path)

        self.preprocessor = getattr(self.model, "named_steps", {}).get("preprocessor")
        self.classifier = getattr(self.model, "named_steps", {}).get("classifier")
        self.feature_names = self._extract_feature_names()

        self._shap_explainer = None
        self.shap_available = bool(shap is not None and self.preprocessor is not None and self.classifier is not None)

        self.threshold_policy = ThresholdPolicy.from_env()
        self.channel_prior_weight = _parse_float_env("CHANNEL_PRIOR_WEIGHT", 1.0, 0.0, 2.0)
        self.channel_prior_min_sample = _parse_int_env("CHANNEL_PRIOR_MIN_SAMPLE", 200, 20, 100000)
        self.channel_prior_smoothing = _parse_float_env("CHANNEL_PRIOR_SMOOTHING", 200.0, 0.0, 100000.0)
        self.channel_prior_max_odds_ratio = _parse_float_env("CHANNEL_PRIOR_MAX_ODDS_RATIO", 3.0, 1.0, 20.0)

        self.calibration_enabled = _parse_bool_env("ENABLE_CONFIDENCE_CALIBRATION", True)
        self.persist_calibrator = _parse_bool_env("PERSIST_CALIBRATOR", False)
        self.calibration_data_path = os.getenv("CALIBRATION_DATA_PATH", os.path.join("data", "processed", "processed_cyber_data.csv"))
        self.calibrator_path = os.getenv("CALIBRATOR_PATH", os.path.join("models", "probability_calibrator.joblib"))
        self.calibration_max_rows = _parse_int_env("CALIBRATION_MAX_ROWS", 15000, 1000, 200000)

        self._probability_calibrator = None
        self.calibration_method = "none"
        self.calibration_applied = False
        self._initialize_calibrator()

        self.channel_profiler = ChannelSegmentProfiler(self.calibration_data_path, logger=self.logger)

    def _initialize_calibrator(self) -> None:
        if not self.calibration_enabled:
            self.logger.info("Confidence calibration disabled by configuration")
            return

        if self._load_calibrator_from_disk():
            return

        if not os.path.exists(self.calibration_data_path):
            self.logger.warning("Calibration data not found at %s. Using raw model probabilities.", self.calibration_data_path)
            return

        try:
            df = pd.read_csv(self.calibration_data_path)
        except Exception as exc:  # pragma: no cover - environment dependent
            self.logger.warning("Failed to read calibration data: %s", exc)
            return

        required_columns = {"processed_text", "has_dangerous_link", "contains_urgency", "label"}
        missing_columns = required_columns - set(df.columns)
        if missing_columns:
            self.logger.warning("Calibration data missing columns: %s", sorted(missing_columns))
            return

        calib_df = df[["processed_text", "has_dangerous_link", "contains_urgency", "label"]].copy()
        calib_df = calib_df.dropna(subset=["processed_text", "label"])

        if calib_df.empty or calib_df["label"].nunique() < 2:
            self.logger.warning("Calibration dataset is not suitable. Using raw model probabilities.")
            return

        if len(calib_df) > self.calibration_max_rows:
            calib_df = calib_df.sample(n=self.calibration_max_rows, random_state=42)

        features = calib_df[["processed_text", "has_dangerous_link", "contains_urgency"]]
        labels = calib_df["label"].astype(int)

        try:
            raw_probabilities = self.model.predict_proba(features)[:, 1].reshape(-1, 1)
            raw_probabilities = np.clip(raw_probabilities, 1e-6, 1.0 - 1e-6)
            calibrator = LogisticRegression(max_iter=1000, random_state=42, solver="liblinear")
            calibrator.fit(raw_probabilities, labels)
        except Exception as exc:  # pragma: no cover - model/runtime dependent
            self.logger.warning("Failed to fit calibration model: %s", exc)
            return

        self._probability_calibrator = calibrator
        self.calibration_method = "platt_sigmoid"
        self.calibration_applied = True
        if self.persist_calibrator:
            self._persist_calibrator_to_disk()
        self.logger.info("Confidence calibration is active (%s).", self.calibration_method)

    def _load_calibrator_from_disk(self) -> bool:
        if not self.calibrator_path or not os.path.exists(self.calibrator_path):
            return False

        try:
            payload = joblib.load(self.calibrator_path)
        except Exception as exc:  # pragma: no cover - filesystem dependent
            self.logger.warning("Failed to load calibrator from %s: %s", self.calibrator_path, exc)
            return False

        if isinstance(payload, dict):
            calibrator = payload.get("model")
            method = payload.get("method", "platt_sigmoid")
        else:
            calibrator = payload
            method = "platt_sigmoid"

        if calibrator is None:
            return False

        self._probability_calibrator = calibrator
        self.calibration_method = method
        self.calibration_applied = True
        self.logger.info("Loaded probability calibrator from %s", self.calibrator_path)
        return True

    def _persist_calibrator_to_disk(self) -> None:
        if self._probability_calibrator is None or not self.calibrator_path:
            return

        try:
            calibrator_dir = os.path.dirname(self.calibrator_path)
            if calibrator_dir:
                os.makedirs(calibrator_dir, exist_ok=True)
            payload = {"method": self.calibration_method, "model": self._probability_calibrator}
            joblib.dump(payload, self.calibrator_path)
        except Exception as exc:  # pragma: no cover - filesystem dependent
            self.logger.warning("Failed to persist calibrator: %s", exc)

    def _apply_calibration(self, raw_probability: float) -> float:
        bounded_raw = _clip_probability(raw_probability)
        if not self.calibration_applied or self._probability_calibrator is None:
            return bounded_raw

        try:
            calibrated = float(self._probability_calibrator.predict_proba(np.asarray([[bounded_raw]], dtype=float))[0][1])
        except Exception as exc:  # pragma: no cover - runtime fallback path
            self.logger.warning("Calibration predict failed; using raw probability: %s", exc)
            return bounded_raw

        return _clip_probability(calibrated)

    def _extract_feature_names(self) -> List[str]:
        if self.preprocessor is None:
            return []

        try:
            names = self.preprocessor.get_feature_names_out()
            return [str(name) for name in names]
        except Exception:
            pass

        names: List[str] = []
        transformers = getattr(self.preprocessor, "transformers_", [])

        for _, transformer, columns in transformers:
            if transformer == "drop":
                continue

            if transformer == "passthrough":
                if isinstance(columns, str):
                    names.append(columns)
                else:
                    names.extend([str(col) for col in columns])
                continue

            if hasattr(transformer, "get_feature_names_out"):
                try:
                    if isinstance(columns, (list, tuple, np.ndarray)):
                        feature_names = transformer.get_feature_names_out(columns)
                    else:
                        feature_names = transformer.get_feature_names_out()
                    names.extend([str(feature_name) for feature_name in feature_names])
                except Exception:
                    if isinstance(columns, str):
                        names.append(columns)
                    else:
                        names.extend([str(col) for col in columns])
                continue

            if isinstance(columns, str):
                names.append(columns)
            else:
                names.extend([str(col) for col in columns])

        return names

    def _get_shap_explainer(self):
        if self._shap_explainer is None:
            self._shap_explainer = shap.TreeExplainer(self.classifier)
        return self._shap_explainer

    def _humanize_feature_name(self, feature_name: str) -> str:
        if "has_dangerous_link" in feature_name:
            return "indikator tautan berbahaya"
        if "contains_urgency" in feature_name:
            return "indikator bahasa mendesak"
        if "platform" in feature_name:
            return "indikator sumber pesan"
        if "__" in feature_name:
            _, raw_feature = feature_name.split("__", 1)
            return f"kata kunci '{raw_feature}'"
        return feature_name

    def _build_reasoning_from_contributor(self, contributor: Dict[str, Any]) -> str:
        label = contributor["feature"]
        impact = contributor["impact"]

        if impact == "increase_risk":
            return f"{label.capitalize()} meningkatkan skor risiko pesan ini."
        return f"{label.capitalize()} menurunkan skor risiko pesan ini."

    def _parse_shap_values(self, shap_values: Any) -> np.ndarray:
        if isinstance(shap_values, list):
            if len(shap_values) > 1:
                return np.asarray(shap_values[1][0], dtype=float)
            return np.asarray(shap_values[0][0], dtype=float)

        values = np.asarray(shap_values)

        if values.ndim == 1:
            return values.astype(float)
        if values.ndim == 2:
            return values[0].astype(float)
        if values.ndim == 3:
            if values.shape[-1] == 2:
                return values[0, :, 1].astype(float)
            if values.shape[0] == 2:
                return values[1, 0, :].astype(float)

        raise ValueError("Unsupported SHAP output shape for binary classifier")

    def _explain_with_shap(self, features_df: pd.DataFrame, top_k: int = 5) -> List[Dict[str, Any]]:
        if not self.shap_available or not self.feature_names:
            return []

        transformed = self.preprocessor.transform(features_df)
        transformed_row = transformed.toarray() if hasattr(transformed, "toarray") else np.asarray(transformed)

        explainer = self._get_shap_explainer()
        shap_values = explainer.shap_values(transformed_row)
        local_contrib = self._parse_shap_values(shap_values)

        row_values = transformed_row[0]
        feature_count = min(len(local_contrib), len(self.feature_names), len(row_values))

        scored_features: List[Dict[str, Any]] = []
        for idx in range(feature_count):
            contribution = float(local_contrib[idx])
            if abs(contribution) < 1e-12:
                continue

            raw_feature = self.feature_names[idx]
            feature_value = float(row_values[idx])

            if raw_feature.startswith("text__") and feature_value <= 0.0:
                continue

            scored_features.append(
                {
                    "feature": self._humanize_feature_name(raw_feature),
                    "raw_feature": raw_feature,
                    "contribution": round(contribution, 6),
                    "impact": "increase_risk" if contribution > 0 else "decrease_risk",
                    "value": round(feature_value, 6),
                }
            )

        scored_features.sort(key=lambda item: abs(item["contribution"]), reverse=True)
        return scored_features[:top_k]

    def _heuristic_reasoning(
        self,
        text: str,
        features_payload: Dict[str, List[Any]],
        is_phishing: bool,
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        text_lower = text.lower()
        has_link = bool(features_payload["has_dangerous_link"][0])
        has_urgency = bool(features_payload["contains_urgency"][0])

        reasoning: List[str] = []
        contributors: List[Dict[str, Any]] = []

        if ".apk" in text_lower:
            reasoning.append("Terdapat indikasi file .apk yang sering dipakai pada serangan phishing/malware.")
            contributors.append(
                {
                    "feature": "indikator tautan berbahaya (.apk)",
                    "raw_feature": "heuristic_apk",
                    "contribution": 1.0,
                    "impact": "increase_risk",
                    "value": 1.0,
                }
            )

        if has_link:
            reasoning.append("Terdapat pola tautan mencurigakan seperti shortlink, domain tidak umum, atau format IP.")
            contributors.append(
                {
                    "feature": "indikator tautan berbahaya",
                    "raw_feature": "has_dangerous_link",
                    "contribution": 1.0,
                    "impact": "increase_risk",
                    "value": 1.0,
                }
            )

        if has_urgency:
            reasoning.append("Terdapat bahasa desakan yang mendorong tindakan cepat tanpa verifikasi.")
            contributors.append(
                {
                    "feature": "indikator bahasa mendesak",
                    "raw_feature": "contains_urgency",
                    "contribution": 1.0,
                    "impact": "increase_risk",
                    "value": 1.0,
                }
            )

        if not reasoning and not is_phishing:
            reasoning.append("Tidak terdeteksi indikator kuat tautan berbahaya maupun bahasa mendesak.")
            contributors.append(
                {
                    "feature": "indikator tautan berbahaya",
                    "raw_feature": "has_dangerous_link",
                    "contribution": -1.0,
                    "impact": "decrease_risk",
                    "value": float(features_payload["has_dangerous_link"][0]),
                }
            )
            contributors.append(
                {
                    "feature": "indikator bahasa mendesak",
                    "raw_feature": "contains_urgency",
                    "contribution": -1.0,
                    "impact": "decrease_risk",
                    "value": float(features_payload["contains_urgency"][0]),
                }
            )

        if not reasoning:
            reasoning.append("Model mendeteksi pola teks yang mirip dengan karakteristik phishing.")

        return reasoning, contributors[:5]

    def _build_mitigation_tip(self, is_phishing: bool, features_payload: Dict[str, List[Any]], text: str) -> str:
        text_lower = text.lower()

        if not is_phishing:
            return "Pesan cenderung aman, namun tetap verifikasi identitas pengirim sebelum membagikan data pribadi."

        if ".apk" in text_lower:
            return "Jangan unduh atau instal file .apk dari pesan tidak dikenal. Gunakan hanya sumber aplikasi resmi."
        if bool(features_payload["has_dangerous_link"][0]):
            return "Jangan klik tautan yang dikirim pengirim tidak dikenal. Verifikasi lewat kanal resmi terlebih dahulu."
        if bool(features_payload["contains_urgency"][0]):
            return "Abaikan tekanan untuk bertindak cepat. Luangkan waktu verifikasi ke pihak resmi."

        return "Hindari membagikan OTP, PIN, kata sandi, atau data pribadi tanpa verifikasi sumber pesan."

    def _merge_reasoning(self, primary: List[str], contextual: List[str], max_items: int = 5) -> List[str]:
        merged: List[str] = []
        seen = set()

        for item in primary + contextual:
            normalized = item.strip()
            if not normalized or normalized in seen:
                continue
            merged.append(normalized)
            seen.add(normalized)
            if len(merged) >= max_items:
                break

        return merged

    def analyze_text(
        self,
        text: str,
        source: Optional[str] = None,
        sensitivity: Optional[str] = None,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        features_payload = extract_inference_features(text)
        features_df = pd.DataFrame(features_payload)

        processed_text = features_payload["processed_text"][0]
        channel = normalize_channel(source)

        probabilities = self.model.predict_proba(features_df)[0]
        raw_threat_probability = float(probabilities[1])
        calibrated_threat_probability = self._apply_calibration(raw_threat_probability)

        channel_adjusted_probability, prior_adjustment = self.channel_profiler.adjust_probability(
            calibrated_threat_probability,
            channel,
            weight=self.channel_prior_weight,
            min_sample=self.channel_prior_min_sample,
            smoothing=self.channel_prior_smoothing,
            max_odds_ratio=self.channel_prior_max_odds_ratio,
        )

        policy = self.threshold_policy.resolve(sensitivity=sensitivity, channel=channel)
        decision_threshold = float(policy["decision_threshold"])

        is_phishing = bool(channel_adjusted_probability >= decision_threshold)
        confidence = round(channel_adjusted_probability * 100.0, 2)
        uncertainty_flag = abs(channel_adjusted_probability - decision_threshold) <= self.threshold_policy.uncertainty_margin

        xai_method = "heuristic_fallback"
        top_contributors: List[Dict[str, Any]] = []

        if self.shap_available:
            try:
                top_contributors = self._explain_with_shap(features_df, top_k=top_k)
                if top_contributors:
                    xai_method = "shap"
            except Exception as exc:  # pragma: no cover - runtime fallback path
                self.logger.warning("SHAP explainability failed, fallback to heuristics: %s", exc)

        if xai_method == "shap":
            reasoning = [self._build_reasoning_from_contributor(item) for item in top_contributors[:3]]
        else:
            reasoning, top_contributors = self._heuristic_reasoning(text, features_payload, is_phishing)

        channel_context_reasoning, channel_analysis = self.channel_profiler.build_channel_context(
            channel=channel,
            processed_text=processed_text,
            features_payload=features_payload,
        )
        reasoning = self._merge_reasoning(reasoning, channel_context_reasoning)

        if is_phishing and uncertainty_flag:
            message = "Pesan berada di zona abu-abu namun melewati ambang kebijakan dan ditandai berisiko PHISHING."
        elif is_phishing:
            message = "Pesan ini terdeteksi berisiko PHISHING."
        elif uncertainty_flag:
            message = "Pesan berada di zona abu-abu dan saat ini diklasifikasikan AMAN oleh kebijakan threshold."
        else:
            message = "Pesan ini cenderung AMAN dari pola phishing."

        mitigation_tip = self._build_mitigation_tip(is_phishing, features_payload, text)
        if uncertainty_flag:
            mitigation_tip += " Nilai risiko dekat ambang keputusan, lakukan verifikasi manual tambahan."

        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "message": message,
            "reasoning": reasoning,
            "mitigation_tip": mitigation_tip,
            "xai_method": xai_method,
            "top_contributors": top_contributors,
            "uncertainty_flag": uncertainty_flag,
            "source": source,
            "calibration": {
                "applied": self.calibration_applied,
                "method": self.calibration_method,
                "raw_probability": round(raw_threat_probability * 100.0, 2),
                "calibrated_probability": round(calibrated_threat_probability * 100.0, 2),
                "channel_adjusted_probability": round(channel_adjusted_probability * 100.0, 2),
            },
            "threshold_policy": {
                "sensitivity": policy["sensitivity"],
                "mode": policy["mode"],
                "channel": policy["channel"],
                "base_threshold": round(float(policy["base_threshold"]) * 100.0, 2),
                "channel_offset": round(float(policy["channel_offset"]) * 100.0, 2),
                "decision_threshold": round(decision_threshold * 100.0, 2),
                "uncertainty_margin": round(self.threshold_policy.uncertainty_margin * 100.0, 2),
            },
            "channel_analysis": {
                **channel_analysis,
                "prior_global": prior_adjustment["global_prior"],
                "prior_channel": prior_adjustment["channel_prior"],
                "prior_adjustment_applied": prior_adjustment["applied"],
                "prior_odds_ratio": prior_adjustment["odds_ratio"],
                "prior_min_sample": prior_adjustment["min_sample"],
                "prior_smoothing": prior_adjustment["smoothing"],
                "smoothed_prior_channel": prior_adjustment["smoothed_channel_prior"],
                "channel_prior_weight": round(self.channel_prior_weight, 2),
            },
        }

    def get_runtime_status(self) -> Dict[str, Any]:
        return {
            "model_loaded": self.model is not None,
            "shap_available": self.shap_available,
            "calibration": {
                "enabled": self.calibration_enabled,
                "applied": self.calibration_applied,
                "method": self.calibration_method,
                "calibration_data_path": self.calibration_data_path,
                "calibrator_path": self.calibrator_path,
                "persist_calibrator": self.persist_calibrator,
            },
            "threshold_policy": self.threshold_policy.get_config(),
            "channel_segmentation": {
                "channel_prior_weight": round(self.channel_prior_weight, 2),
                "channel_prior_min_sample": self.channel_prior_min_sample,
                "channel_prior_smoothing": round(self.channel_prior_smoothing, 2),
                "channel_prior_max_odds_ratio": round(self.channel_prior_max_odds_ratio, 2),
                "profiles": {
                    key: {
                        "sample_size": int(value["sample_size"]),
                        "prior_phishing": round(float(value["prior_phishing"]) * 100.0, 2),
                        "mean_tokens": round(float(value["mean_tokens"]), 2),
                        "std_tokens": round(float(value["std_tokens"]), 2),
                        "link_rate": round(float(value["link_rate"]) * 100.0, 2),
                        "urgency_rate": round(float(value["urgency_rate"]) * 100.0, 2),
                    }
                    for key, value in self.channel_profiler.channel_profiles.items()
                },
            },
        }
