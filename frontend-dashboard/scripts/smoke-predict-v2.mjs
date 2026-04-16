const baseUrl = (process.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

const payload = {
  text: "PERINGATAN! Akun Anda diblokir, segera verifikasi di bit.ly/cek-akun sekarang juga.",
  source: "SMS",
  sensitivity: "balanced",
};

const requiredTopLevel = [
  "is_phishing",
  "confidence",
  "message",
  "reasoning",
  "mitigation_tip",
  "xai_method",
  "top_contributors",
  "uncertainty_flag",
  "calibration",
  "threshold_policy",
  "channel_analysis",
];

const requiredNested = {
  calibration: ["raw_probability", "calibrated_probability", "channel_adjusted_probability"],
  threshold_policy: ["sensitivity", "mode", "channel", "decision_threshold"],
  channel_analysis: ["channel", "token_count", "prior_odds_ratio"],
};

function assertHasKeys(obj, keys, label) {
  for (const key of keys) {
    if (!(key in obj)) {
      throw new Error(`[smoke] Missing key '${key}' in ${label}`);
    }
  }
}

async function main() {
  const response = await fetch(`${baseUrl}/predict-v2`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const fallback = await response.text().catch(() => "");
    throw new Error(`[smoke] API error ${response.status}: ${fallback}`);
  }

  const result = await response.json();
  assertHasKeys(result, requiredTopLevel, "root response");

  for (const [section, keys] of Object.entries(requiredNested)) {
    if (typeof result[section] !== "object" || result[section] === null) {
      throw new Error(`[smoke] Section '${section}' must be an object`);
    }
    assertHasKeys(result[section], keys, section);
  }

  if (typeof result.confidence !== "number" || result.confidence < 0 || result.confidence > 100) {
    throw new Error("[smoke] Confidence is out of expected 0-100 range");
  }

  console.log(`[smoke] OK | confidence=${result.confidence.toFixed(2)} | xai=${result.xai_method}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
