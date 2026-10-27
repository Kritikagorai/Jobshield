/**
 * JobShield Frontend Application Core (app.js)
 * Powers:
 * 1. Multimodal Fraud Scanner (Text, URL, Email, Phone, OCR)
 * 2. Theme Toggle (Dark/Light with localStorage persistence)
 * 3. Salary Reality Check Tool (Indian MCA & NASSCOM market benchmarks)
 * 4. Recruiter Domain & Email Mismatch Checker (with SSRF protection)
 * 5. Payment & Personal Data Red-Flag Advisor ("Should I Pay?")
 * 6. Scam Syndicate Indicator Profile Telemetry Search
 * 7. Shareable Cryptographic Report Cards
 */

let activeTab = "text";
let selectedFile = null;
let latestScanId = null;

// Embedded sample presets for 1-click zero-latency testing
const SAMPLE_PRESETS = {
  genuine: `TATA CONSULTANCY SERVICES LIMITED
Corporate Identification Number (CIN): L22210MH1995PLC084781
GSTIN: 27AAACT2876H1ZW
Registered Office: TCS House, Raveline Street, Fort, Mumbai 400 001, India.
Website: https://www.tcs.com | Official Careers: campus-recruitment@tcs.com

Ref: TCS/OFFER/2026/ASE/892110
Subject: Letter of Offer - Assistant System Engineer - Trainee
Gross Annual Total Compensation (CTC): INR 3,85,000/- per annum.
TCS adheres strictly to a zero-fee recruitment policy. You are not required to pay any deposit, registration fee, equipment courier charge, or training expense at any point.`,

  laptop_scam: `TATA CONSULTANCY SERVICES RECRUITMENT HUB (INDIA)
OFFICIAL APPOINTMENT LETTER & DIRECT SELECTION ORDER
Registration No: TCS-HR-2026-CONFIDENTIAL
Recruitment Email: hr.tcsrecruitment@gmail.com
WhatsApp: +91 98765 43210 | Telegram: @tcs_career_desk
Portal: www.tcs-hiring-portal.online

POST OFFERED: Senior Associate IT Analyst & Trainee
MONTHLY SALARY: INR 85,000/- Per Month + Free Cab & Medical Insurance
You have been directly shortlisted without written test or interview.
Deposit a REFUNDABLE SECURITY & COURIER INSURANCE AMOUNT OF INR 2,999/- TODAY BEFORE 6:00 PM via Google Pay/PhonePe to UPI ID: hr.tcslogistics@icici.
WARNING: If screenshot is not sent on WhatsApp within 2 HOURS, legal notice will be dispatched under IPC Section 420.`,

  airport_scam: `AVIATION STAR CREW MANAGEMENT PVT LTD
Urgent Direct Recruitment for Airport Cargo Ground Staff & Ticketing Executive in Delhi / Mumbai Airport.
10th and 12th pass eligible. No written examination required.
Fixed Salary: INR 35,000 to 55,000 per month with free accommodation and meals.
Recruiter WhatsApp: +91 91234 56789 | Email: airport.careers.in@gmail.com
Pay gate pass medical verification and uniform measurement fee Rs 2,500 immediately to UPI ID: airporthelpdesk@icici.`,

  typing_scam: `OFFLINE DATA ENTRY & TYPING SOLUTIONS
Earn Rs 30,000 monthly by typing simple manuscript pages at home. 500 pages in 10 days.
Accuracy 90% required. Daily payout via UPI.
Before starting work, pay digital agreement stamp duty and software login charges of Rs 1,850 via Google Pay to HR Pooja on Telegram @hrmanager_pooja.
Early contract termination will incur Rs 10,000 legal notice penalty.`
};

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  setupTabs();
  setupDropzone();
  setupFormSubmit();
  setupSalaryRealityForm();
  setupDomainCheckForm();
  setupPaymentAdvisorForm();
  setupIndicatorSearchForm();
  fetchLiveStats();
});

/* ============================================================
   1. THEME MANAGEMENT (Light Default with localStorage persistence)
   ============================================================ */
function initTheme() {
  const saved = localStorage.getItem("jobshield_theme") || "light";
  document.documentElement.setAttribute("data-theme", saved);
  updateThemeToggleUI(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("jobshield_theme", next);
  updateThemeToggleUI(next);
}

function updateThemeToggleUI(theme) {
  const icon = document.getElementById("theme-icon");
  const text = document.getElementById("theme-text");
  if (theme === "dark") {
    if (icon) icon.textContent = "🌙";
    if (text) text.textContent = "Dark";
  } else {
    if (icon) icon.textContent = "🌓";
    if (text) text.textContent = "Light";
  }
}

/* ============================================================
   2. TOOL SWITCHER (Home Page Multi-Tool Navigation)
   ============================================================ */
function switchTool(toolId) {
  document.querySelectorAll(".tool-tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-tool") === toolId);
  });
  document.querySelectorAll(".tool-panel").forEach(panel => {
    panel.style.display = panel.id === `tool-panel-${toolId}` ? "block" : "none";
  });
  // Smooth scroll into tool view
  const activePanel = document.getElementById(`tool-panel-${toolId}`);
  if (activePanel) {
    activePanel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

/* ============================================================
   3. SAMPLE PRESET LOADERS
   ============================================================ */
function loadPreset(presetKey) {
  const text = SAMPLE_PRESETS[presetKey];
  if (!text) return;

  switchTool("scanner");
  const textTabBtn = document.querySelector('.tab-btn[data-tab="text"]');
  if (textTabBtn) textTabBtn.click();

  const textArea = document.getElementById("input-text");
  if (textArea) {
    textArea.value = text;
    textArea.focus();
  }
}

/* ============================================================
   4. MULTIMODAL SCANNER TABS & DROPZONE
   ============================================================ */
function setupTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));

      tab.classList.add("active");
      activeTab = tab.getAttribute("data-tab");
      const targetContent = document.getElementById(`tab-content-${activeTab}`);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });
}

function setupDropzone() {
  const dropzone = document.getElementById("file-dropzone");
  const fileInput = document.getElementById("file-input");
  const fileInfo = document.getElementById("file-selected-info");

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener("click", () => fileInput.click());

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      selectedFile = e.target.files[0];
      fileInfo.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      fileInfo.style.display = "inline-block";
    }
  });

  ["dragenter", "dragover"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(evt => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      selectedFile = e.dataTransfer.files[0];
      fileInfo.textContent = `Selected: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
      fileInfo.style.display = "inline-block";
    }
  });
}

/* ============================================================
   5. SCANNER FORM SUBMIT & RESULT DISPLAY
   ============================================================ */
function setupFormSubmit() {
  const checkBtn = document.getElementById("check-btn");
  if (!checkBtn) return;

  checkBtn.addEventListener("click", async () => {
    const textInput = document.getElementById("input-text")?.value.trim() || "";
    const urlInput = document.getElementById("input-url")?.value.trim() || "";
    const emailInput = document.getElementById("input-email")?.value.trim() || "";
    const phoneInput = document.getElementById("input-phone")?.value.trim() || "";
    const companyInput = document.getElementById("input-company-name")?.value.trim() || "";

    if (activeTab === "text" && !textInput) {
      alert("Please enter or paste the job description or offer text.");
      return;
    }
    if (activeTab === "url" && !urlInput) {
      alert("Please enter the job or recruiter website URL.");
      return;
    }
    if (activeTab === "contact" && !emailInput && !phoneInput) {
      alert("Please provide at least a recruiter email address or phone number.");
      return;
    }
    if (activeTab === "upload" && !selectedFile) {
      alert("Please select or drop an offer letter or document file.");
      return;
    }

    const loadingBox = document.getElementById("loading-box");
    const resultBox = document.getElementById("result-container");
    const stepText = document.getElementById("loading-step-text");

    if (resultBox) resultBox.style.display = "none";
    if (loadingBox) loadingBox.style.display = "block";

    const loadingSteps = [
      "Reading document details & extracting credentials...",
      "Validating company registry & corporate domains...",
      "Scikit-Learn ML similarity matching against scam templates...",
      "Checking community fraud reports & syndicate graph...",
      "Generating explainable Trust Score & risk checklist..."
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      currentStep = (currentStep + 1) % loadingSteps.length;
      if (stepText) stepText.textContent = loadingSteps[currentStep];
    }, 450);

    try {
      const formData = new FormData();
      if (textInput) formData.append("text", textInput);
      if (urlInput) formData.append("url", urlInput);
      if (emailInput) formData.append("email", emailInput);
      if (phoneInput) formData.append("phone", phoneInput);
      if (companyInput) formData.append("company_name", companyInput);
      if (selectedFile && activeTab === "upload") {
        formData.append("file", selectedFile);
      }

      const response = await fetch("/analyze", {
        method: "POST",
        body: formData
      });

      clearInterval(interval);
      if (loadingBox) loadingBox.style.display = "none";

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: "Analysis failed" }));
        alert(`Error: ${err.detail || "Unable to analyze. Please check your input."}`);
        return;
      }

      const data = await response.json();
      latestScanId = data.scan_id;
      displayResult(data);
    } catch (error) {
      clearInterval(interval);
      if (loadingBox) loadingBox.style.display = "none";
      alert("Could not connect to JobShield backend. Please verify the server is running.");
      console.error(error);
    }
  });
}

function displayResult(data) {
  const resultBox = document.getElementById("result-container");
  const gaugeCircle = document.getElementById("gauge-circle");
  const gaugeScore = document.getElementById("gauge-score");
  const verdictBadge = document.getElementById("verdict-badge");
  const confidenceText = document.getElementById("confidence-text");
  const reasonsList = document.getElementById("reasons-list");
  const dangerBanner = document.getElementById("danger-banner");
  const disclaimerText = document.getElementById("disclaimer-text");
  const entityContainer = document.getElementById("entity-chips-container");
  const mlMatchBadge = document.getElementById("ml-pattern-match-badge");
  const shareBtn = document.getElementById("share-report-card-btn");

  if (!resultBox) return;

  const score = data.trust_score || 0;
  if (gaugeScore) gaugeScore.textContent = score;

  if (gaugeCircle) {
    gaugeCircle.className = "gauge-circle";
    if (score >= 70) gaugeCircle.classList.add("gauge-safe");
    else if (score >= 40) gaugeCircle.classList.add("gauge-suspicious");
    else gaugeCircle.classList.add("gauge-scam");
  }

  if (verdictBadge) {
    verdictBadge.className = "verdict-badge";
    if (score >= 70) verdictBadge.classList.add("verdict-safe");
    else if (score >= 40) verdictBadge.classList.add("verdict-suspicious");
    else verdictBadge.classList.add("verdict-scam");
    verdictBadge.textContent = data.verdict;
  }

  if (confidenceText) {
    confidenceText.textContent = `Confidence: ${data.confidence || "High"} • Linked Reports: ${data.linked_reports_count || 0}`;
  }

  // Update direction explanation
  const directionElem = document.getElementById("score-direction-text");
  if (directionElem) {
    directionElem.textContent = data.score_direction || "Higher = Safer (0 = Dangerous Scam, 100 = Likely Genuine)";
  }

  // Danger Banner for payment demand or critical threat
  if (dangerBanner) {
    const hasCritical = (data.reasons || []).some(r => r.severity === "critical" || r.title.toLowerCase().includes("payment") || r.title.toLowerCase().includes("fee"));
    if (hasCritical || score < 50) {
      dangerBanner.style.display = "block";
    } else {
      dangerBanner.style.display = "none";
    }
  }

  // ML Pattern Match Banner
  if (mlMatchBadge && data.ml_match) {
    if (data.ml_match.matched) {
      mlMatchBadge.style.display = "inline-flex";
      mlMatchBadge.innerHTML = `🤖 <strong>AI Modus Match:</strong> ${escapeHtml(data.ml_match.category)} (${data.ml_match.similarity_percentage}% Match)`;
    } else {
      mlMatchBadge.style.display = "none";
    }
  }

  // Populate Positive and Warning Breakdowns if containers exist
  const positiveList = document.getElementById("positive-indicators-list");
  if (positiveList && data.positive_indicators) {
    positiveList.innerHTML = "";
    data.positive_indicators.forEach(p => {
      const li = document.createElement("li");
      li.innerHTML = `✅ ${escapeHtml(p)}`;
      positiveList.appendChild(li);
    });
  }

  const warningList = document.getElementById("warning-signs-list");
  if (warningList && data.warning_signs) {
    warningList.innerHTML = "";
    data.warning_signs.forEach(w => {
      const li = document.createElement("li");
      li.innerHTML = `🚨 ${escapeHtml(w)}`;
      warningList.appendChild(li);
    });
  }

  // Populate Reasons
  if (reasonsList) {
    reasonsList.innerHTML = "";
    (data.reasons || []).forEach(r => {
      const li = document.createElement("li");
      li.className = `reason-item ${r.severity || "medium"}`;

      let iconChar = "⚠️";
      if (r.severity === "critical" || r.severity === "high") iconChar = "🚨";
      if (r.severity === "low") iconChar = "✅";

      li.innerHTML = `
        <div class="reason-icon">${iconChar}</div>
        <div class="reason-content">
          <div class="reason-title">${escapeHtml(r.title)}</div>
          <div class="reason-desc">${escapeHtml(r.description)}</div>
        </div>
      `;
      reasonsList.appendChild(li);
    });
  }

  // Populate Extracted Entities
  if (entityContainer && data.extracted_entities) {
    const ent = data.extracted_entities;
    let chipsHtml = "";
    if (ent.company_name) chipsHtml += `<span class="entity-pill">🏢 Company: ${escapeHtml(ent.company_name)}</span>`;
    if (ent.cin) chipsHtml += `<span class="entity-pill pill-cin">🏢 CIN: ${escapeHtml(ent.cin)}</span>`;
    if (ent.gstin) chipsHtml += `<span class="entity-pill pill-gstin">📑 GSTIN: ${escapeHtml(ent.gstin)}</span>`;
    (ent.upi_ids || []).forEach(u => chipsHtml += `<span class="entity-pill pill-upi">💳 UPI: ${escapeHtml(u)}</span>`);
    (ent.phones || []).forEach(p => chipsHtml += `<span class="entity-pill pill-phone">📞 ${escapeHtml(p)}</span>`);
    (ent.emails || []).forEach(e => chipsHtml += `<span class="entity-pill">✉️ ${escapeHtml(e)}</span>`);
    (ent.salaries || []).forEach(s => chipsHtml += `<span class="entity-pill">💰 ${escapeHtml(s)}</span>`);
    entityContainer.innerHTML = chipsHtml || `<span style="font-size: 0.85rem; color: var(--slate-500);">No structured credentials extracted</span>`;
  }

  // Wire Share Button
  if (shareBtn && data.scan_id) {
    shareBtn.style.display = "inline-flex";
    shareBtn.onclick = () => {
      const url = `${window.location.origin}/report-card.html?id=${data.scan_id}`;
      navigator.clipboard.writeText(url).then(() => {
        showToast("Shareable Report Card URL copied to clipboard!");
      }).catch(() => {
        window.open(`/report-card.html?id=${data.scan_id}`, "_blank");
      });
    };
  }

  if (disclaimerText && data.disclaimer) {
    disclaimerText.textContent = data.disclaimer;
  }

  resultBox.style.display = "block";
  resultBox.scrollIntoView({ behavior: "smooth" });
}

/* ============================================================
   6. SALARY REALITY CHECK TOOL
   ============================================================ */
function setupSalaryRealityForm() {
  const btn = document.getElementById("salary-check-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const role = document.getElementById("salary-role")?.value.trim() || "";
    const company = document.getElementById("salary-company")?.value.trim() || "";
    const city = document.getElementById("salary-city")?.value || "";
    const exp = document.getElementById("salary-exp")?.value || "fresher";
    const salary = parseFloat(document.getElementById("salary-amount")?.value || "0");
    const period = document.getElementById("salary-period")?.value || "monthly";
    const empType = document.getElementById("salary-emp-type")?.value || "full-time";

    if (!role) {
      alert("Please enter a job role / designation (e.g., Software Engineer, Data Entry, Digital Marketing).");
      return;
    }

    const loadingBox = document.getElementById("salary-loading");
    const resultBox = document.getElementById("salary-result-box");
    if (resultBox) resultBox.style.display = "none";
    if (loadingBox) loadingBox.style.display = "block";

    try {
      const res = await fetch("/api/salary-reality-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          role,
          company_name: company,
          location: city,
          experience_level: exp,
          advertised_salary: salary,
          period,
          employment_type: empType
        })
      });

      if (loadingBox) loadingBox.style.display = "none";

      if (!res.ok) {
        alert("Failed to evaluate salary reality. Please verify your inputs.");
        return;
      }

      const data = await res.json();
      renderSalaryResult(data);
    } catch (e) {
      if (loadingBox) loadingBox.style.display = "none";
      alert("Could not reach JobShield Salary Reality API.");
      console.error(e);
    }
  });
}

function renderSalaryResult(data) {
  const box = document.getElementById("salary-result-box");
  if (!box) return;

  const badge = document.getElementById("salary-verdict-badge");
  const verdictText = document.getElementById("salary-verdict-text");
  const explanation = document.getElementById("salary-explanation-text");
  const statsGrid = document.getElementById("salary-stats-grid");
  const citations = document.getElementById("salary-citations-text");

  if (badge) {
    badge.className = "salary-ratio-badge";
    if (data.is_realistic && data.role_verified) {
      badge.classList.add("ratio-normal");
      badge.textContent = "✅ Realistic Market Compensation";
    } else if (data.task_scam_warning || data.status === "EXTREME_ANOMALY") {
      badge.classList.add("ratio-extreme");
      badge.textContent = "🚨 Extreme Anomaly (Task Scam Bait Warning)";
    } else if (!data.role_verified) {
      badge.classList.add("ratio-warning");
      badge.textContent = "ℹ️ Unverified Role Designation";
    } else {
      badge.classList.add("ratio-warning");
      badge.textContent = `⚠️ Advertised Salary Diverges (${data.anomaly_ratio || 1.0}x Market)`;
    }
  }

  if (verdictText) verdictText.textContent = data.verdict;
  if (explanation) explanation.textContent = data.explanation;

  if (statsGrid && data.market_benchmark) {
    const mb = data.market_benchmark;
    statsGrid.innerHTML = `
      <div class="bench-box">
        <div class="bench-box-label">Advertised Package</div>
        <div class="bench-box-val" style="color: var(--accent-blue);">${escapeHtml(data.advertised_salary?.formatted_monthly || "₹0")}</div>
        <div style="font-size: 0.75rem; color: var(--slate-500);">${escapeHtml(data.advertised_salary?.formatted_annual || "")}</div>
      </div>
      <div class="bench-box">
        <div class="bench-box-label">Market Minimum</div>
        <div class="bench-box-val">${mb.monthly_min_inr ? `₹${mb.monthly_min_inr.toLocaleString()}` : "N/A"}</div>
        <div style="font-size: 0.75rem; color: var(--slate-500);">${mb.annual_min_lpa ? `₹${mb.annual_min_lpa} LPA` : ""}</div>
      </div>
      <div class="bench-box">
        <div class="bench-box-label">Market Median</div>
        <div class="bench-box-val" style="color: var(--safe-green-text);">${mb.monthly_median_inr ? `₹${mb.monthly_median_inr.toLocaleString()}` : "N/A"}</div>
        <div style="font-size: 0.75rem; color: var(--slate-500);">${mb.annual_median_lpa ? `₹${mb.annual_median_lpa} LPA` : ""}</div>
      </div>
      <div class="bench-box">
        <div class="bench-box-label">Market Upper Band</div>
        <div class="bench-box-val">${mb.monthly_max_inr ? `₹${mb.monthly_max_inr.toLocaleString()}` : "N/A"}</div>
        <div style="font-size: 0.75rem; color: var(--slate-500);">${mb.annual_max_lpa ? `₹${mb.annual_max_lpa} LPA` : ""}</div>
      </div>
    `;
  }

  if (citations) {
    citations.textContent = `Data Sources: ${(data.citations || ["NASSCOM Indian IT Survey", "AmbitionBox Aggregates"]).join(" • ")}. Notice: High compensation alone is an anomaly signal, not automated proof of fraud.`;
  }

  box.style.display = "block";
  box.scrollIntoView({ behavior: "smooth" });
}

/* ============================================================
   7. RECRUITER DOMAIN MISMATCH CHECKER
   ============================================================ */
function setupDomainCheckForm() {
  const btn = document.getElementById("domain-check-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const emailOrDomain = document.getElementById("domain-input-email")?.value.trim() || "";
    const company = document.getElementById("domain-input-company")?.value.trim() || "";
    const url = document.getElementById("domain-input-url")?.value.trim() || "";

    if (!emailOrDomain && !url) {
      alert("Please enter a recruiter email, domain (e.g., hr.tcs@gmail.com), or portal URL.");
      return;
    }

    const loadingBox = document.getElementById("domain-loading");
    const resultBox = document.getElementById("domain-result-box");
    if (resultBox) resultBox.style.display = "none";
    if (loadingBox) loadingBox.style.display = "block";

    try {
      const res = await fetch("/api/check-recruiter-domain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email_or_domain: emailOrDomain,
          company_name: company,
          url: url
        })
      });

      if (loadingBox) loadingBox.style.display = "none";

      if (!res.ok) {
        alert("Failed to analyze domain. Please check your inputs.");
        return;
      }

      const data = await res.json();
      renderDomainResult(data);
    } catch (e) {
      if (loadingBox) loadingBox.style.display = "none";
      alert("Could not reach Domain Checker API.");
      console.error(e);
    }
  });
}

function renderDomainResult(data) {
  const box = document.getElementById("domain-result-box");
  if (!box) return;

  const badge = document.getElementById("domain-verdict-badge");
  const warningsList = document.getElementById("domain-warnings-list");
  const verifiedList = document.getElementById("domain-verified-list");
  const detailsBox = document.getElementById("domain-details-box");

  if (badge) {
    badge.className = "verdict-badge";
    if (data.is_mismatch) {
      badge.classList.add("verdict-scam");
      badge.textContent = `🚨 Domain Mismatch Detected (${data.mismatch_severity || "High Risk"})`;
    } else if (data.is_free_email) {
      badge.classList.add("verdict-suspicious");
      badge.textContent = "⚠️ Free Webmail Recruiter Alert";
    } else {
      badge.classList.add("verdict-safe");
      badge.textContent = "✅ Official Corporate Domain Match";
    }
  }

  if (detailsBox) {
    detailsBox.innerHTML = `
      <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem;">
        <span class="domain-audit-pill" style="background: var(--slate-100); border: 1px solid var(--slate-200); color: var(--navy-800);">
          🌐 Inspected Domain: <strong>${escapeHtml(data.inspected_domain || "N/A")}</strong>
        </span>
        <span class="domain-audit-pill" style="background: var(--slate-100); border: 1px solid var(--slate-200); color: var(--navy-800);">
          🏢 Claimed Company: <strong>${escapeHtml(data.claimed_company || "Unspecified")}</strong>
        </span>
        ${data.is_free_email ? '<span class="domain-audit-pill" style="background: var(--danger-red-bg); color: var(--danger-red-text);">⚠️ Free Public Webmail</span>' : ''}
        ${data.is_typosquat ? `<span class="domain-audit-pill" style="background: var(--danger-red-bg); color: var(--danger-red-text);">🚨 Typosquats ${escapeHtml(data.target_brand || "")}</span>` : ''}
        ${data.url_safe === false ? '<span class="domain-audit-pill" style="background: var(--danger-red-bg); color: var(--danger-red-text);">🛡️ SSRF Blocked / Unsafe URL</span>' : ''}
      </div>
    `;
  }

  if (warningsList) {
    warningsList.innerHTML = "";
    const signs = data.warning_signs && data.warning_signs.length ? data.warning_signs : ["No explicit brand lookalike anomalies observed."];
    signs.forEach(s => {
      const li = document.createElement("li");
      li.innerHTML = `🚨 ${escapeHtml(s)}`;
      warningsList.appendChild(li);
    });
  }

  if (verifiedList) {
    verifiedList.innerHTML = "";
    const verified = data.verified_findings && data.verified_findings.length ? data.verified_findings : ["Verification dependent on company registry match."];
    verified.forEach(v => {
      const li = document.createElement("li");
      li.innerHTML = `✅ ${escapeHtml(v)}`;
      verifiedList.appendChild(li);
    });
  }

  box.style.display = "block";
  box.scrollIntoView({ behavior: "smooth" });
}

/* ============================================================
   8. PAYMENT & IDENTITY RED-FLAG ADVISOR ("Should I Pay?")
   ============================================================ */
function setupPaymentAdvisorForm() {
  const btn = document.getElementById("payment-advisor-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const text = document.getElementById("payment-advisor-text")?.value.trim() || "";
    if (!text) {
      alert("Please paste the message or communication asking for fees, laptop deposit, Aadhaar, or OTP.");
      return;
    }

    const loadingBox = document.getElementById("payment-loading");
    const resultBox = document.getElementById("payment-result-box");
    if (resultBox) resultBox.style.display = "none";
    if (loadingBox) loadingBox.style.display = "block";

    try {
      const res = await fetch("/api/payment-advisory", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });

      if (loadingBox) loadingBox.style.display = "none";

      if (!res.ok) {
        alert("Failed to analyze payment request.");
        return;
      }

      const data = await res.json();
      renderPaymentResult(data);
    } catch (e) {
      if (loadingBox) loadingBox.style.display = "none";
      alert("Could not reach Payment Advisory API.");
      console.error(e);
    }
  });
}

function loadPaymentPreset(type) {
  const ta = document.getElementById("payment-advisor-text");
  if (!ta) return;
  switchTool("payment");

  if (type === "laptop") {
    ta.value = "Congratulations on your selection as Software Analyst! You must deposit a refundable security charge of Rs 2,999/- for courier insurance and laptop dispatch via Google Pay / PhonePe to hr.tcs@okaxis today.";
  } else if (type === "otp") {
    ta.value = "To activate your company direct salary account with HDFC Bank, please immediately share the 6-digit OTP verification code received on your mobile phone.";
  } else if (type === "pan") {
    ta.value = "Please send unmasked color photos of your original Aadhaar Card and PAN Card on WhatsApp to this number before we can generate your offer letter.";
  }
}

function renderPaymentResult(data) {
  const box = document.getElementById("payment-result-box");
  if (!box) return;

  const otpAlert = document.getElementById("payment-otp-critical-alert");
  const verdictBadge = document.getElementById("payment-verdict-badge");
  const verdictTitle = document.getElementById("payment-verdict-title");
  const adviceText = document.getElementById("payment-primary-advice");
  const redFlagsContainer = document.getElementById("payment-red-flags-container");
  const checklist = document.getElementById("payment-checklist");
  const maskedContent = document.getElementById("payment-masked-content");

  if (otpAlert) {
    otpAlert.style.display = data.critical_warning_otp ? "flex" : "none";
  }

  if (verdictBadge) {
    verdictBadge.className = "verdict-badge";
    if (data.overall_severity === "SAFE") {
      verdictBadge.classList.add("verdict-safe");
      verdictBadge.textContent = "✅ SAFE: No Payment Demanded";
    } else if (data.overall_severity === "CRITICAL_THREAT") {
      verdictBadge.classList.add("verdict-scam");
      verdictBadge.textContent = "🚨 CRITICAL THEFT ATTEMPT";
    } else {
      verdictBadge.classList.add("verdict-scam");
      verdictBadge.textContent = "🛑 DO NOT PAY ANY MONEY";
    }
  }

  if (verdictTitle) verdictTitle.textContent = data.verdict_title;
  if (adviceText) adviceText.textContent = data.primary_advice;

  if (redFlagsContainer) {
    redFlagsContainer.innerHTML = "";
    (data.detected_warnings || []).forEach(w => {
      const div = document.createElement("div");
      div.style.cssText = "background: var(--slate-100); border: 1px solid var(--slate-200); padding: 1rem; border-radius: var(--radius-sm); margin-bottom: 0.75rem;";
      div.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
          <strong style="color: var(--danger-red-text);">${escapeHtml(w.title)}</strong>
          <span class="pillar-badge fail">${escapeHtml(w.severity)}</span>
        </div>
        <p style="font-size: 0.88rem; color: var(--navy-800); margin: 0 0 0.4rem;">${escapeHtml(w.why_unsafe)}</p>
        <div style="font-size: 0.82rem; color: var(--accent-blue);"><strong>Safer Alternative:</strong> ${escapeHtml(w.safer_verification)}</div>
      `;
      redFlagsContainer.appendChild(div);
    });
  }

  if (checklist) {
    checklist.innerHTML = "";
    (data.action_checklist || []).forEach(step => {
      const li = document.createElement("li");
      li.innerHTML = `<span>🛡️</span> <span>${escapeHtml(step)}</span>`;
      checklist.appendChild(li);
    });
  }

  if (maskedContent && data.masked_content) {
    maskedContent.textContent = data.masked_content;
  }

  box.style.display = "block";
  box.scrollIntoView({ behavior: "smooth" });
}

/* ============================================================
   9. SCAM SYNDICATE INDICATOR PROFILE SEARCH
   ============================================================ */
function setupIndicatorSearchForm() {
  const btn = document.getElementById("indicator-search-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    const input = document.getElementById("indicator-search-input")?.value.trim() || "";
    if (!input) {
      alert("Please enter a phone (+91 98765 43210), UPI ID (hr@icici), domain, or company name.");
      return;
    }

    const loadingBox = document.getElementById("indicator-loading");
    const resultBox = document.getElementById("indicator-result-box");
    if (resultBox) resultBox.style.display = "none";
    if (loadingBox) loadingBox.style.display = "block";

    try {
      const res = await fetch(`/api/indicator/${encodeURIComponent(input)}`);
      if (loadingBox) loadingBox.style.display = "none";

      if (!res.ok) {
        alert("Failed to query indicator profile.");
        return;
      }

      const data = await res.json();
      renderIndicatorResult(data);
    } catch (e) {
      if (loadingBox) loadingBox.style.display = "none";
      alert("Could not reach Syndicate Intelligence API.");
      console.error(e);
    }
  });
}

function quickSearchIndicator(val) {
  switchTool("indicator");
  const inp = document.getElementById("indicator-search-input");
  if (inp) {
    inp.value = val;
    document.getElementById("indicator-search-btn")?.click();
  }
}

function renderIndicatorResult(data) {
  const box = document.getElementById("indicator-result-box");
  if (!box) return;

  const header = document.getElementById("indicator-header");
  const stats = document.getElementById("indicator-stats-grid");
  const assoc = document.getElementById("indicator-associated-box");
  const reportsList = document.getElementById("indicator-reports-list");

  if (header) {
    header.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem;">
        <div>
          <span style="font-size: 0.75rem; font-weight: 800; color: var(--slate-500); text-transform: uppercase;">Indicator Profile</span>
          <h3 style="color: var(--navy-900); margin: 0.2rem 0; font-family: var(--font-mono);">${escapeHtml(data.indicator)}</h3>
        </div>
        <span class="domain-audit-pill" style="background: ${data.found ? 'var(--danger-red-bg)' : 'var(--safe-green-bg)'}; color: ${data.found ? 'var(--danger-red-text)' : 'var(--safe-green-text)'};">
          ${escapeHtml(data.status_label)}
        </span>
      </div>
    `;
  }

  if (stats) {
    stats.innerHTML = `
      <div class="bench-box">
        <div class="bench-box-label">Corroborating Reports</div>
        <div class="bench-box-val" style="color: var(--danger-red-text);">${data.report_count || 0}</div>
      </div>
      <div class="bench-box">
        <div class="bench-box-label">Total Demanded</div>
        <div class="bench-box-val">₹${(data.total_demanded_inr || 0).toLocaleString()}</div>
      </div>
      <div class="bench-box">
        <div class="bench-box-label">Confidence</div>
        <div class="bench-box-val" style="font-size: 0.95rem; color: var(--navy-800);">${escapeHtml(data.confidence_level)}</div>
      </div>
    `;
  }

  if (assoc && data.associated_indicators) {
    const a = data.associated_indicators;
    assoc.innerHTML = `
      <h5 style="margin-bottom: 0.5rem; color: var(--navy-900);">Associated Syndicate Nodes (Masked PII)</h5>
      <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
        ${(a.upis || []).map(u => `<span class="domain-audit-pill" style="background: var(--danger-red-bg); color: var(--danger-red-text);">💳 ${escapeHtml(u)}</span>`).join('')}
        ${(a.phones || []).map(p => `<span class="domain-audit-pill" style="background: var(--slate-100); color: var(--navy-800);">📞 ${escapeHtml(p)}</span>`).join('')}
        ${(a.domains || []).map(d => `<span class="domain-audit-pill" style="background: var(--accent-blue-subtle); color: var(--accent-blue);">🌐 ${escapeHtml(d)}</span>`).join('')}
        ${(a.companies || []).map(c => `<span class="domain-audit-pill" style="background: var(--slate-100); color: var(--navy-800);">🏢 ${escapeHtml(c)}</span>`).join('')}
      </div>
    `;
  }

  if (reportsList && data.recent_reports) {
    reportsList.innerHTML = "";
    if (data.recent_reports.length === 0) {
      reportsList.innerHTML = `<p style="font-size: 0.88rem; color: var(--slate-500);">No community scam complaints on record for this indicator.</p>`;
    } else {
      data.recent_reports.forEach(rep => {
        const item = document.createElement("div");
        item.style.cssText = "background: var(--slate-100); border: 1px solid var(--slate-200); padding: 0.85rem 1rem; border-radius: var(--radius-sm); margin-bottom: 0.6rem; font-size: 0.86rem;";
        item.innerHTML = `
          <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
            <strong>${escapeHtml(rep.scam_type || "Job Scam")}</strong>
            <span style="color: var(--danger-red-text); font-weight: 700;">₹${(rep.amount_demanded || 0).toLocaleString()} Demanded</span>
          </div>
          <div style="color: var(--slate-500); font-size: 0.8rem;">
            Company: ${escapeHtml(rep.company_name || "Unspecified")} • City: ${escapeHtml(rep.city || "Pan-India")} • Date: ${escapeHtml(rep.created_at || "Recent")}
          </div>
        `;
        reportsList.appendChild(item);
      });
    }
  }

  box.style.display = "block";
  box.scrollIntoView({ behavior: "smooth" });
}

/* ============================================================
   10. LIVE METRIC TELEMETRY & TOAST UTILITIES
   ============================================================ */
async function fetchLiveStats() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const stats = await res.json();

    const countElem = document.getElementById("stat-total-reports");
    const amountElem = document.getElementById("stat-prevented-amount");
    const companiesElem = document.getElementById("stat-companies-count");

    if (countElem && stats.total_reports) countElem.textContent = `${stats.total_reports}+`;
    if (amountElem && stats.total_scam_amount_inr) amountElem.textContent = `₹${(stats.total_scam_amount_inr / 100000).toFixed(1)}L+`;
    if (companiesElem && stats.registered_companies) companiesElem.textContent = `${stats.registered_companies}+`;
  } catch (e) {
    console.log("Stats fetch skipped:", e);
  }
}

function showToast(msg) {
  const toast = document.createElement("div");
  toast.className = "jobshield-toast";
  toast.innerHTML = `<span>🛡️</span> <span>${escapeHtml(msg)}</span>`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3200);
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
