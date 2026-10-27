/**
 * Internationalization (i18n) module for JobShield.
 * Supports seamless switching between English and Hindi.
 */
const translations = {
  en: {
    tagline: "Scam hone se pehle pakdo",
    subtitle: "Verify job offers, recruiter contacts & offer letters before paying money or sharing personal documents.",
    tab_text: "Job Description",
    tab_url: "Job / Company URL",
    tab_contact: "Email or Phone",
    tab_upload: "Upload File / Letter",
    btn_check: "Check Now",
    loading_1: "Reading document details...",
    loading_2: "Checking company credentials...",
    loading_3: "Checking recruiter domain & email...",
    loading_4: "Scanning community scam reports...",
    loading_5: "Calculating explainable Trust Score...",
    warning_fee: "CRITICAL ALERT: Payment Demanded! Genuine employers NEVER ask candidates for registration fees, training charges, or security deposits.",
    score_safe: "Safe / Likely Genuine",
    score_suspicious: "Suspicious – Exercise Caution",
    score_scam: "High Scam Probability",
    should_i_pay_title: "Should I Pay?",
    should_i_pay_text: "NO! Legitimate corporate employers bear 100% of recruiting and equipment costs. Asking candidates to pay any amount is the #1 hallmark of employment fraud."
  },
  hi: {
    tagline: "स्कैम होने से पहले पकड़ो",
    subtitle: "पैसे देने या दस्तावेज़ साझा करने से पहले नौकरी के ऑफ़र, रिक्रूटर के संपर्क और ऑफ़र लेटर की जांच करें।",
    tab_text: "जॉब विवरण (Text)",
    tab_url: "वेबसाइट / यूआरएल",
    tab_contact: "ईमेल या फ़ोन",
    tab_upload: "फ़ाइल / ऑफ़र लेटर अपलोड",
    btn_check: "अभी जांचें (Check Now)",
    loading_1: "दस्तावेज़ पढ़ा जा रहा है...",
    loading_2: "कंपनी की पहचान जांची जा रही है...",
    loading_3: "रिक्रूटर डोमेन व ईमेल की जांच...",
    loading_4: "स्कैम डेटाबेस में खोज जारी है...",
    loading_5: "ट्रस्ट स्कोर तैयार किया जा रहा है...",
    warning_fee: "सावधान! पैसे की मांग की गई है! असली कंपनियां कभी भी रजिस्ट्रेशन फीस, ट्रेनिंग चार्ज या लैपटॉप डिपॉजिट नहीं मांगतीं।",
    score_safe: "सुरक्षित / असली प्रतीत होता है",
    score_suspicious: "संदिग्ध – सावधानी बरतें",
    score_scam: "स्कैम होने की अत्यधिक संभावना",
    should_i_pay_title: "क्या मुझे पैसे देने चाहिए?",
    should_i_pay_text: "बिल्कुल नहीं! कोई भी प्रतिष्ठित कंपनी नौकरी के लिए पैसे नहीं लेती। पैसे मांगना 100% धोखेबाज़ी का संकेत है।"
  }
};

let currentLang = "en";

function setLanguage(lang) {
  if (!translations[lang]) return;
  currentLang = lang;
  document.querySelectorAll("[data-i18n]").forEach(elem => {
    const key = elem.getAttribute("data-i18n");
    if (translations[lang][key]) {
      elem.textContent = translations[lang][key];
    }
  });
  const toggleBtn = document.getElementById("lang-toggle-btn");
  if (toggleBtn) {
    toggleBtn.textContent = lang === "en" ? "🇮🇳 हिंदी" : "🌐 English";
  }
}

function toggleLanguage() {
  setLanguage(currentLang === "en" ? "hi" : "en");
}
