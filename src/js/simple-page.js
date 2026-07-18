import { initLanguage } from "./language.js";
import { isScamResult } from "./result-verdict.js";

const TERMS_KEY = "safemind-terms-choice-v3";
const EXPERIENCE_KEY = "safemind-page-experience-v1";
try {
  if (localStorage.getItem(TERMS_KEY) !== "accepted") window.location.replace("/");
  else if (localStorage.getItem(EXPERIENCE_KEY) === "standard") window.location.replace("/");
} catch { /* The simple page remains available if storage is blocked. */ }

const form = document.getElementById("simpleChecker");
const input = document.getElementById("simpleInput");
const checkButton = document.getElementById("simpleCheckButton");
const status = document.getElementById("simpleStatus");
const answer = document.getElementById("simpleAnswer");
const tutorial = document.getElementById("simpleTutorial");
const tutorialVideo = document.getElementById("simpleTutorialVideo");
const nlpServiceUrl = import.meta.env.VITE_NLP_API_URL || "/api/spam-check";
const locale = () => document.documentElement.lang === "my" ? "my" : "en";
const say = (en, my) => locale() === "my" ? my : en;

function detectType(value) {
  const text = value.trim();
  if (/^(?:from|subject|to):/im.test(text) && /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/i.test(text)) return "email";
  if (/^(?:https?:\/\/|www\.)\S+/i.test(text)) return "link";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(text)) return "email";
  if (/^\+?[\d\s().-]{7,22}$/.test(text)) return "phone";
  return "message";
}

function show(dialog) { if (dialog && !dialog.open) dialog.showModal(); }
function close(dialog) { if (dialog?.open) dialog.close(); }

async function analyzeWithNlpService(content) {
  const scanType = detectType(content);
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 45_000);
  try {
    const response = await fetch(nlpServiceUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
      body: JSON.stringify({ scan_type: scanType, content })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || result.detail || "The OpenAI analysis service is unavailable.");
    return result;
  } finally {
    window.clearTimeout(timeout);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const content = input.value.trim();
  if (content.length < 3) {
    status.textContent = say("Paste a message before checking.", "မစစ်ဆေးမီ စာသားတစ်ခု ထည့်ပါ။");
    input.focus();
    return;
  }
  checkButton.disabled = true;
  checkButton.textContent = say("CHECKING…", "စစ်ဆေးနေသည်…");
  const progressSteps = [
    say("Connecting to AI…", "AI နှင့် ချိတ်ဆက်နေသည်…"),
    say("Scanning warning signs…", "သတိပေးလက္ခဏာများ စစ်ဆေးနေသည်…"),
    say("Preparing your result…", "သင့်ရလဒ်ကို ပြင်ဆင်နေသည်…")
  ];
  let progressIndex = 0;
  status.textContent = progressSteps[progressIndex];
  const progressTimer = window.setInterval(() => {
    progressIndex = (progressIndex + 1) % progressSteps.length;
    status.textContent = progressSteps[progressIndex];
  }, 2200);
  answer.hidden = true;
  try {
    const result = await analyzeWithNlpService(content);
    const risky = isScamResult(result);
    const risk = ["HIGH", "MEDIUM", "LOW"].includes(String(result.risk || "").toUpperCase())
      ? String(result.risk).toUpperCase()
      : risky ? "HIGH" : "LOW";
    document.getElementById("simpleVerdict").textContent = risk === "HIGH"
      ? say("SCAM · HIGH RISK", "လိမ်လည်မှု · အန္တရာယ်မြင့်")
      : risk === "MEDIUM"
        ? say("SCAM · MEDIUM RISK", "လိမ်လည်မှု · အန္တရာယ်အလယ်အလတ်")
        : say("NOT SCAM · LOW RISK", "လိမ်လည်မှုမဟုတ် · အန္တရာယ်နည်း");
    document.getElementById("simpleVerdict").dataset.risk = risk.toLowerCase();
    document.getElementById("simpleSummary").textContent = risky
      ? say("Stop. Do not click, reply, or send money until you verify this yourself.", "ရပ်တန့်ပါ။ ကိုယ်တိုင်အတည်မပြုမချင်း လင့်ခ်မနှိပ်၊ စာမပြန်၊ ငွေမပို့ပါနှင့်။")
      : say("No strong scam signs were found. Still verify unexpected requests yourself.", "ပြင်းထန်သော လိမ်လည်မှုလက္ခဏာ မတွေ့ပါ။ မမျှော်လင့်သော တောင်းဆိုချက်များကို ကိုယ်တိုင်အတည်ပြုပါ။");
    const actions = risky
      ? [say("Do not send money", "ငွေမပို့ပါနှင့်"), say("Do not share an OTP or password", "OTP သို့မဟုတ် စကားဝှက် မမျှဝေပါနှင့်"), say("Call the organization using its official number", "အဖွဲ့အစည်း၏ တရားဝင်နံပါတ်ကို ခေါ်ပါ")]
      : [say("Verify unexpected requests", "မမျှော်လင့်သော တောင်းဆိုချက်ကို အတည်ပြုပါ"), say("Keep passwords and OTP codes private", "စကားဝှက်နှင့် OTP ကုဒ်ကို လျှို့ဝှက်ထားပါ")];
    document.getElementById("simpleActions").replaceChildren(...actions.map((text) => { const li = document.createElement("li"); li.textContent = text; return li; }));
    answer.hidden = false;
    answer.scrollIntoView({ behavior:"smooth", block:"start" });
    status.textContent = say("Check complete.", "စစ်ဆေးမှု ပြီးပါပြီ။");
  } catch (error) {
    status.textContent = error?.name === "AbortError"
      ? say("The check took too long. Please try again.", "စစ်ဆေးမှု အချိန်ကြာနေပါသည်။ ထပ်မံကြိုးစားပါ။")
      : say("We could not finish the check. Your content is still here. Please try again.", "စစ်ဆေးမှု မပြီးဆုံးနိုင်ပါ။ သင့်အကြောင်းအရာ မပျောက်ပါ။ ထပ်မံကြိုးစားပါ။");
  } finally {
    window.clearInterval(progressTimer);
    checkButton.disabled = false;
    checkButton.textContent = say("CHECK NOW", "ယခု စစ်ဆေးရန်");
  }
});

const THEME_KEY = "safemind-theme";
function applyTheme(theme, persist = true) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  document.documentElement.style.colorScheme = next;
  document.querySelectorAll("[data-set-theme]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.setTheme === next)));
  if (persist) { try { localStorage.setItem(THEME_KEY, next); } catch { /* The choice still applies on this page when storage is blocked. */ } }
}
document.querySelectorAll("[data-set-theme]").forEach((button) => button.addEventListener("click", () => applyTheme(button.dataset.setTheme)));
window.addEventListener("storage", (event) => {
  if (event.key === THEME_KEY && (event.newValue === "light" || event.newValue === "dark")) applyTheme(event.newValue, false);
});
applyTheme(document.documentElement.dataset.theme, false);

document.getElementById("simpleAgain").addEventListener("click", () => { answer.hidden = true; input.focus(); form.scrollIntoView({behavior:"smooth"}); });
document.querySelectorAll("[data-open-simple-tutorial],[data-tutorial-topic]").forEach((button) => button.addEventListener("click", () => show(tutorial)));
document.querySelectorAll("[data-close-simple-tutorial]").forEach((button) => button.addEventListener("click", () => close(tutorial)));
tutorial?.addEventListener("close", () => tutorialVideo?.pause());
initLanguage();
