const inputText = document.getElementById("inputText");
const sourceSelect = document.getElementById("sourceSelect");
const sensitivitySelect = document.getElementById("sensitivitySelect");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const resultCard = document.getElementById("resultCard");
const resultLabel = document.getElementById("resultLabel");
const resultScore = document.getElementById("resultScore");
const resultMessage = document.getElementById("resultMessage");
const resultMeta = document.getElementById("resultMeta");
const confidenceBar = document.getElementById("confidenceBar");
const reasoningList = document.getElementById("reasoningList");
const contributors = document.getElementById("contributors");
const mitigationTip = document.getElementById("mitigationTip");
const apiError = document.getElementById("apiError");
const metricRuns = document.getElementById("metricRuns");
const metricAvg = document.getElementById("metricAvg");
const metricHigh = document.getElementById("metricHigh");
const checkQuizBtn = document.getElementById("checkQuizBtn");
const quizFeedback = document.getElementById("quizFeedback");

const sessionState = {
  runs: 0,
  sumRisk: 0,
  highRisk: 0,
};

const urgencyRegex = /(segera|darurat|blokir|denda|hangus|peringatan|terakhir)/i;
const linkRegex = /(http|www\.|bit\.ly|tinyurl|s\.id|\.[a-z]{2,3}\/)/i;
const credentialRegex = /(otp|pin|password|kata sandi|nik|ktp|cvv)/i;
const baitRegex = /(hadiah|cashback|gratis|menang|promo besar)/i;

function applyScenario(text) {
  inputText.value = text;
  inputText.focus();
}

function setChecklist(text) {
  const flags = {
    hasLink: linkRegex.test(text),
    hasUrgency: urgencyRegex.test(text),
    asksCredential: credentialRegex.test(text),
    tooGood: baitRegex.test(text),
  };

  document.querySelectorAll("#flagChecklist li").forEach((item) => {
    const flagName = item.dataset.flag;
    item.classList.toggle("active", Boolean(flags[flagName]));
  });
}

function updateMetrics(confidence, isPhishing) {
  sessionState.runs += 1;
  sessionState.sumRisk += confidence;
  if (isPhishing || confidence >= 75) {
    sessionState.highRisk += 1;
  }

  metricRuns.textContent = String(sessionState.runs);
  metricAvg.textContent = `${(sessionState.sumRisk / sessionState.runs).toFixed(2)}%`;
  metricHigh.textContent = String(sessionState.highRisk);
}

function renderContributors(topContributors) {
  contributors.innerHTML = "";

  if (!topContributors || topContributors.length === 0) {
    contributors.innerHTML = "<p>Kontributor tidak tersedia untuk hasil ini.</p>";
    return;
  }

  topContributors.forEach((item) => {
    const row = document.createElement("div");
    row.className = "contributor-item";

    const directionClass = item.impact === "increase_risk" ? "impact-up" : "impact-down";
    const directionLabel = item.impact === "increase_risk" ? "Meningkatkan Risiko" : "Menurunkan Risiko";

    row.innerHTML = `
      <span>${item.feature}</span>
      <span class="${directionClass}">${directionLabel} (${Math.abs(item.contribution).toFixed(3)})</span>
    `;

    contributors.appendChild(row);
  });
}

function showResult(data) {
  const score = Number(data.confidence || 0);
  const isHigh = Boolean(data.is_phishing);

  resultCard.hidden = false;
  resultLabel.textContent = isHigh ? "Risiko Tinggi: PHISHING Terdeteksi" : "Risiko Rendah: Pesan Relatif Aman";
  resultLabel.classList.toggle("risk-high", isHigh);
  resultLabel.classList.toggle("risk-low", !isHigh);

  resultScore.textContent = `${score.toFixed(2)}%`;
  confidenceBar.style.width = `${Math.min(score, 100)}%`;

  resultMessage.textContent = data.message || "Analisis selesai.";

  const threshold = data.threshold_policy
    ? `Threshold ${Number(data.threshold_policy.decision_threshold).toFixed(2)}% (${data.threshold_policy.sensitivity})`
    : "Threshold tidak tersedia";

  const xaiMethod = data.xai_method || "-";
  const uncertainty = data.uncertainty_flag ? "Borderline: perlu verifikasi manual ekstra" : "Keyakinan model stabil";
  resultMeta.textContent = `${threshold} • XAI: ${xaiMethod} • ${uncertainty}`;

  reasoningList.innerHTML = "";
  const reasons = Array.isArray(data.reasoning) && data.reasoning.length > 0
    ? data.reasoning
    : ["Tidak ada reasoning yang dikembalikan model."];

  reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasoningList.appendChild(li);
  });

  mitigationTip.textContent = data.mitigation_tip || "Verifikasi lewat kanal resmi sebelum mengambil tindakan.";
  renderContributors(data.top_contributors);
  updateMetrics(score, isHigh);
}

async function analyzeMessage() {
  const text = inputText.value.trim();
  if (!text) {
    apiError.hidden = false;
    apiError.textContent = "Masukkan teks terlebih dahulu sebelum analisis.";
    return;
  }

  setChecklist(text);
  apiError.hidden = true;
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Menganalisis...";

  try {
    const response = await fetch("/predict-v2", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        text,
        source: sourceSelect.value,
        sensitivity: sensitivitySelect.value,
      }),
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      const detail = payload.detail || "Terjadi kesalahan saat meminta analisis ke API.";
      throw new Error(typeof detail === "string" ? detail : "API tidak dapat memproses permintaan.");
    }

    const data = await response.json();
    showResult(data);
  } catch (error) {
    apiError.hidden = false;
    apiError.textContent = error.message;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analisis Pesan";
  }
}

function clearForm() {
  inputText.value = "";
  apiError.hidden = true;
  resultCard.hidden = true;
  confidenceBar.style.width = "0";
  document.querySelectorAll("#flagChecklist li").forEach((item) => item.classList.remove("active"));
}

function checkQuiz() {
  const selected = document.querySelector('input[name="quiz"]:checked');
  if (!selected) {
    quizFeedback.textContent = "Pilih salah satu jawaban dulu.";
    quizFeedback.className = "quiz-feedback nope";
    return;
  }

  if (selected.value === "right") {
    quizFeedback.textContent = "Benar. Jangan pernah membagikan OTP, lakukan verifikasi via kanal resmi.";
    quizFeedback.className = "quiz-feedback ok";
    return;
  }

  quizFeedback.textContent = "Belum tepat. OTP bersifat rahasia dan tidak boleh dibagikan ke siapa pun.";
  quizFeedback.className = "quiz-feedback nope";
}

analyzeBtn.addEventListener("click", analyzeMessage);
clearBtn.addEventListener("click", clearForm);
checkQuizBtn.addEventListener("click", checkQuiz);

document.querySelectorAll(".chip").forEach((button) => {
  button.addEventListener("click", () => applyScenario(button.dataset.text || ""));
});
