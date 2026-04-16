import { useMemo, useState } from "react";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");

const PRESET_SCENARIOS = [
  {
    id: "account-lock",
    title: "Akun Diblokir",
    source: "SMS",
    sensitivity: "high",
    text: "PERINGATAN! Akun Anda diblokir. Verifikasi di bit.ly/cek-akun dalam 10 menit agar tidak dinonaktifkan permanen.",
  },
  {
    id: "internal-info",
    title: "Informasi Internal",
    source: "WhatsApp",
    sensitivity: "balanced",
    text: "Halo tim, rapat dipindah ke jam 15.00 di ruang utama. Mohon konfirmasi kehadiran.",
  },
  {
    id: "reward-trap",
    title: "Hadiah Palsu",
    source: "Email",
    sensitivity: "high",
    text: "Selamat! Anda terpilih untuk cashback jutaan rupiah. Isi OTP dan PIN Anda di tinyurl.com/bonuscepat sekarang.",
  },
];

const FLAG_RULES = [
  {
    id: "link",
    label: "Ada tautan pendek atau domain tidak familiar",
    pattern: /(bit\.ly|tinyurl|s\.id|http|www\.)/i,
  },
  {
    id: "urgency",
    label: "Bahasa mendesak, ancaman, atau penalti",
    pattern: /(segera|darurat|blokir|penalti|10 menit|terakhir|hangus)/i,
  },
  {
    id: "credential",
    label: "Meminta OTP, PIN, password, atau identitas sensitif",
    pattern: /(otp|pin|password|kata sandi|nik|ktp|cvv)/i,
  },
  {
    id: "bait",
    label: "Iming-iming hadiah berlebihan",
    pattern: /(hadiah|cashback|gratis|jutaan|menang undian)/i,
  },
];

function detectFlags(text) {
  return FLAG_RULES.map((rule) => ({
    ...rule,
    active: rule.pattern.test(text),
  }));
}

function confidenceTone(confidence) {
  if (confidence >= 75) {
    return "high";
  }
  if (confidence >= 45) {
    return "medium";
  }
  return "low";
}

function formatTime(isoString) {
  try {
    return new Date(isoString).toLocaleTimeString("id-ID", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "-";
  }
}

export default function App() {
  const [text, setText] = useState("");
  const [source, setSource] = useState("SMS");
  const [sensitivity, setSensitivity] = useState("balanced");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const flags = useMemo(() => detectFlags(text), [text]);

  const sessionStats = useMemo(() => {
    if (history.length === 0) {
      return {
        totalRuns: 0,
        averageRisk: 0,
        highRiskCount: 0,
      };
    }

    const total = history.length;
    const totalRisk = history.reduce((sum, item) => sum + item.confidence, 0);
    const highRiskCount = history.filter((item) => item.isPhishing || item.confidence >= 75).length;

    return {
      totalRuns: total,
      averageRisk: totalRisk / total,
      highRiskCount,
    };
  }, [history]);

  const recentHistory = useMemo(() => history.slice(0, 5), [history]);

  const onScenarioSelect = (scenario) => {
    setText(scenario.text);
    setSource(scenario.source);
    setSensitivity(scenario.sensitivity);
    setError("");
  };

  const onClear = () => {
    setText("");
    setSource("SMS");
    setSensitivity("balanced");
    setResult(null);
    setError("");
  };

  const onAnalyze = async () => {
    const cleanedText = text.trim();
    if (!cleanedText) {
      setError("Masukkan teks pesan terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/predict-v2`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          text: cleanedText,
          source,
          sensitivity,
        }),
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        const detail = typeof payload.detail === "string" ? payload.detail : "Backend tidak dapat memproses analisis.";
        throw new Error(detail);
      }

      const payload = await response.json();
      const capturedAt = new Date().toISOString();

      const normalizedResult = {
        ...payload,
        confidence: Number(payload.confidence || 0),
        capturedAt,
      };

      setResult(normalizedResult);
      setHistory((prev) => [
        {
          confidence: normalizedResult.confidence,
          isPhishing: normalizedResult.is_phishing,
          source,
          capturedAt,
          snippet: cleanedText.slice(0, 90),
        },
        ...prev,
      ]);
    } catch (analysisError) {
      setError(analysisError.message || "Terjadi kesalahan saat memproses analisis.");
    } finally {
      setLoading(false);
    }
  };

  const tone = confidenceTone(result?.confidence || 0);

  return (
    <div className="app-shell">
      <div className="glow glow-left" aria-hidden="true" />
      <div className="glow glow-right" aria-hidden="true" />

      <header className="hero-card reveal">
        <p className="eyebrow">Frontend Studio Terpisah</p>
        <h1>CyberGuard-ID Community Simulation Hub</h1>
        <p>
          Paket React ini dipisahkan dari backend FastAPI agar tim Frontend/UI-UX bisa iterasi cepat pada desain,
          konten edukasi, dan flow interaksi tanpa mengganggu service model inference.
        </p>
        <div className="api-pill">
          API Endpoint: <span>{API_BASE_URL}/predict-v2</span>
        </div>
      </header>

      <main className="grid-layout">
        <section className="card simulator reveal">
          <div className="card-head">
            <h2>Simulator Phishing</h2>
            <small>Live inference</small>
          </div>

          <div className="scenario-row">
            {PRESET_SCENARIOS.map((scenario) => (
              <button key={scenario.id} type="button" className="scenario-btn" onClick={() => onScenarioSelect(scenario)}>
                {scenario.title}
              </button>
            ))}
          </div>

          <label htmlFor="message">Pesan simulasi</label>
          <textarea
            id="message"
            rows={7}
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Tempel pesan SMS/WhatsApp/Email yang ingin dianalisis"
          />

          <div className="control-grid">
            <div>
              <label htmlFor="source">Sumber</label>
              <select id="source" value={source} onChange={(event) => setSource(event.target.value)}>
                <option value="SMS">SMS</option>
                <option value="WhatsApp">WhatsApp</option>
                <option value="Email">Email</option>
                <option value="Lainnya">Lainnya</option>
              </select>
            </div>

            <div>
              <label htmlFor="sensitivity">Sensitivitas</label>
              <select id="sensitivity" value={sensitivity} onChange={(event) => setSensitivity(event.target.value)}>
                <option value="low">Low</option>
                <option value="balanced">Balanced</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>

          <div className="action-row">
            <button type="button" className="primary" onClick={onAnalyze} disabled={loading}>
              {loading ? "Menganalisis..." : "Analisis Sekarang"}
            </button>
            <button type="button" className="ghost" onClick={onClear}>
              Reset
            </button>
          </div>

          {error ? <p className="error-box">{error}</p> : null}
        </section>

        <section className="card results reveal">
          <div className="card-head">
            <h2>Hasil Analisis</h2>
            <small>Explainable output</small>
          </div>

          {!result ? (
            <p className="empty-state">Jalankan simulasi untuk melihat skor risiko, alasan model, dan tips mitigasi.</p>
          ) : (
            <>
              <div className={`risk-banner ${tone}`}>
                <div>
                  <p className="risk-title">{result.is_phishing ? "Risiko Tinggi" : "Risiko Rendah"}</p>
                  <p className="risk-subtitle">{result.message}</p>
                </div>
                <p className="risk-score">{result.confidence.toFixed(2)}%</p>
              </div>

              <div className="bar-wrap" role="img" aria-label="Persentase risiko phishing">
                <div className={`bar-fill ${tone}`} style={{ width: `${Math.min(result.confidence, 100)}%` }} />
              </div>

              <p className="meta-line">
                Threshold {Number(result.threshold_policy?.decision_threshold || 0).toFixed(2)}% ({result.threshold_policy?.sensitivity || "-"})
                | XAI {result.xai_method || "-"}
              </p>

              <h3>Alasan model</h3>
              <ul>
                {(result.reasoning || []).map((reason, idx) => (
                  <li key={`${reason}-${idx}`}>{reason}</li>
                ))}
              </ul>

              <h3>Top contributors</h3>
              <div className="contributors">
                {(result.top_contributors || []).length === 0 ? (
                  <p>Tidak ada kontributor fitur yang tersedia.</p>
                ) : (
                  result.top_contributors.map((item, idx) => (
                    <div className="contributor" key={`${item.raw_feature}-${idx}`}>
                      <span>{item.feature}</span>
                      <strong className={item.impact === "increase_risk" ? "impact-up" : "impact-down"}>
                        {Math.abs(Number(item.contribution || 0)).toFixed(3)}
                      </strong>
                    </div>
                  ))
                )}
              </div>

              <h3>Mitigasi</h3>
              <p className="tip">{result.mitigation_tip}</p>
            </>
          )}
        </section>

        <section className="card education reveal">
          <div className="card-head">
            <h2>Education Drill Board</h2>
            <small>Awareness</small>
          </div>

          <p className="education-copy">Checklist ini menandai red flags secara otomatis dari teks yang sedang disimulasikan.</p>

          <ul className="flag-list">
            {flags.map((flag) => (
              <li key={flag.id} className={flag.active ? "active" : ""}>
                {flag.label}
              </li>
            ))}
          </ul>

          <h3>Respon Publik 3 Langkah</h3>
          <ol>
            <li>Stop interaksi. Jangan klik tautan dan jangan kirim data apa pun.</li>
            <li>Verifikasi melalui channel resmi instansi atau perusahaan terkait.</li>
            <li>Simpan bukti dan edukasi ulang keluarga atau komunitas sekitar.</li>
          </ol>
        </section>

        <section className="card session reveal">
          <div className="card-head">
            <h2>Sesi Monitoring</h2>
            <small>Learning analytics</small>
          </div>

          <div className="stats-grid">
            <article>
              <p>Total Simulasi</p>
              <h3>{sessionStats.totalRuns}</h3>
            </article>
            <article>
              <p>Rata-rata Risiko</p>
              <h3>{sessionStats.averageRisk.toFixed(2)}%</h3>
            </article>
            <article>
              <p>Kasus Risiko Tinggi</p>
              <h3>{sessionStats.highRiskCount}</h3>
            </article>
          </div>

          <h3>Riwayat Terakhir</h3>
          <div className="history-list">
            {recentHistory.length === 0 ? (
              <p>Belum ada riwayat simulasi.</p>
            ) : (
              recentHistory.map((item, idx) => (
                <div className="history-item" key={`${item.capturedAt}-${idx}`}>
                  <span>{item.source}</span>
                  <span>{item.confidence.toFixed(2)}%</span>
                  <span>{formatTime(item.capturedAt)}</span>
                  <span>{item.snippet}</span>
                </div>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
