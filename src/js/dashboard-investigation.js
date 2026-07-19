import { supabase } from "./backend-client.js";
import { createActionReadiness } from "./action-readiness.js";

const main = document.querySelector("main.dashboard-content");
const workspace = document.getElementById("dashboardInvestigation");
const form = document.getElementById("dashboardScannerForm");
if (main && workspace && form) {
  const STORAGE_KEY = "safemind-dashboard-investigation-v1";
  const quickInput = document.getElementById("quickScanInput");
  const input = document.getElementById("dashboardScanInput");
  const fileInput = document.getElementById("dashboardScanFile");
  const uploadArea = document.getElementById("dashboardScanUploadArea");
  const preview = document.getElementById("dashboardScanFilePreview");
  const previewImage = document.getElementById("dashboardScanFileImage");
  const fileName = document.getElementById("dashboardScanFileName");
  const fileMeta = document.getElementById("dashboardScanFileMeta");
  const status = document.getElementById("dashboardScanStatus");
  const progress = document.getElementById("dashboardScanProgress");
  const progressLabel = document.getElementById("dashboardScanProgressLabel");
  const results = document.getElementById("dashboardScanResults");
  const analyzeButton = document.getElementById("dashboardScanAnalyze");
  const reportButton = document.getElementById("dashboardReportScam");
  const copyButton = document.getElementById("dashboardCopyFinding");
  const exportButton = document.getElementById("dashboardExportAudit");
  const resultsDialog = document.getElementById("dashboardResultsDialog");
  const reportDialog = document.getElementById("investigationReportDialog");
  const reportForm = document.getElementById("investigationReportForm");
  const reportSubmitButton = reportForm.querySelector('button[type="submit"]');
  let selectedFile = null;
  let imagePayload = null;
  let activeResult = null;
  let overviewScroll = 0;
  const quickReadiness = createActionReadiness({ button: document.getElementById("quickScanInvestigate"), controls: [quickInput], isReady: () => quickInput.value.trim().length > 0 });
  const analyzeReadiness = createActionReadiness({ button: analyzeButton, controls: [input, fileInput], isReady: () => input.value.trim().length > 0 || Boolean(imagePayload) });
  const resultReportReadiness = createActionReadiness({ button: reportButton, isReady: () => Boolean(activeResult) });
  const reportSubmitReadiness = createActionReadiness({ button: reportSubmitButton, controls: [document.getElementById("investigationReportNotes")], isReady: () => Boolean(activeResult) });

  const typeCopy = {
    message: ["Suspicious message", "Paste the suspicious message exactly as received..."],
    link: ["Website address", "Paste the complete website address, including https://..."],
    email: ["Email address or email content", "Paste the sender address or suspicious email content..."]
  };
  const visibleTypes = new Set(Object.keys(typeCopy));

  const currentType = () => form.querySelector('input[name="dashboardScanType"]:checked')?.value || "message";
  const setStatus = (message, state = "") => { status.textContent = message; status.dataset.state = state; };
  const formatBytes = (bytes) => bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`;

  function focusMobileInvestigation() {
    if (!window.matchMedia("(max-width: 720px)").matches || workspace.hidden || input.disabled || document.querySelector("dialog[open]")) return;
    window.requestAnimationFrame(() => {
      form.scrollIntoView({ behavior: "auto", block: "start" });
      input.focus({ preventScroll: true });
    });
  }

  function openResultsDialog() {
    if (!activeResult || resultsDialog.open) return;
    resultsDialog.showModal();
    document.body.classList.add("modal-open");
  }

  function closeResultsDialog() {
    if (resultsDialog.open) resultsDialog.close();
    document.body.classList.remove("modal-open");
  }

  function resetAnalyzeButton({ clearResult = false } = {}) {
    analyzeButton.classList.remove("is-complete");
    analyzeButton.dataset.resultReady = "false";
    analyzeButton.textContent = "Analyze with SafeMind";
    if (clearResult) {
      activeResult = null;
      results.hidden = true;
      resultReportReadiness.sync();
      reportSubmitReadiness.sync();
      copyButton.disabled = true;
      exportButton.disabled = true;
    }
  }

  function saveState() {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ type: currentType(), input: input.value, quick: quickInput.value, result: activeResult, investigating: window.SafeMindDashboardSections?.current() === "investigation" || !workspace.hidden, overviewScroll }));
    } catch { /* The scanner remains usable when storage is blocked. */ }
  }

  function updateType(type) {
    const selectedType = visibleTypes.has(type) ? type : "message";
    const radio = form.querySelector(`input[name="dashboardScanType"][value="${selectedType}"]`);
    if (radio) radio.checked = true;
    const [label, placeholder] = typeCopy[selectedType];
    document.getElementById("dashboardScanLabel").textContent = label;
    input.placeholder = placeholder;
    fileInput.accept = "image/png,image/jpeg,image/webp,text/plain,.txt,.eml";
    uploadArea.classList.remove("is-recommended");
    saveState();
  }

  function detectType(value) {
    const text = String(value || "").trim();
    if (/^https?:\/\//i.test(text) || /\bwww\./i.test(text)) return "link";
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return "email";
    return "message";
  }

  function openInvestigation(type = currentType(), preserveScroll = false) {
    if (!preserveScroll) overviewScroll = window.scrollY;
    updateType(type);
    if (window.SafeMindDashboardSections) window.SafeMindDashboardSections.activate("investigation", { scroll: false });
    else { workspace.hidden = false; main.classList.add("is-investigating"); history.replaceState(null, "", "#investigation"); }
    workspace.scrollIntoView({ behavior: "smooth", block: "start" });
    saveState();
  }

  function clearFile() {
    selectedFile = null;
    imagePayload = null;
    fileInput.value = "";
    preview.hidden = true;
    previewImage.hidden = true;
    previewImage.removeAttribute("src");
    fileName.textContent = "";
    fileMeta.textContent = "";
    analyzeReadiness.sync();
  }

  function readFile(file, mode) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(new Error("The selected file could not be read."));
      mode === "data" ? reader.readAsDataURL(file) : reader.readAsText(file);
    });
  }

  async function selectFile(file) {
    if (!file) return;
    resetAnalyzeButton({ clearResult: true });
    const imageTypes = new Set(["image/png", "image/jpeg", "image/webp"]);
    const textTypes = new Set(["text/plain", "message/rfc822"]);
    const isImage = imageTypes.has(file.type);
    const maximumSize = isImage ? 2 * 1024 * 1024 : 5 * 1024 * 1024;
    if (file.size > maximumSize) throw new Error(`Choose ${isImage ? "an image smaller than 2 MB" : "a file smaller than 5 MB"}.`);
    if (!isImage && !textTypes.has(file.type) && !/\.(txt|eml)$/i.test(file.name)) throw new Error("Choose a PNG, JPEG, WebP, TXT, or EML file.");
    clearFile();
    selectedFile = file;
    if (isImage) {
      const dataUrl = await readFile(file, "data");
      imagePayload = { data_url: dataUrl, mime_type: file.type };
      previewImage.src = dataUrl;
      previewImage.hidden = false;
    } else {
      input.value = (await readFile(file, "text")).slice(0, 10000);
    }
    fileName.textContent = file.name;
    fileMeta.textContent = `${isImage ? "Image evidence" : "Text evidence"} · ${formatBytes(file.size)}`;
    preview.hidden = false;
    setStatus("Evidence ready for analysis.", "success");
    analyzeReadiness.sync();
    saveState();
  }

  async function analyzeText(type, content) {
    const apiType = type === "qr" ? (/^https?:\/\//i.test(content) ? "link" : "message") : type;
    const response = await fetch("/api/spam-check", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", cache: "no-store", body: JSON.stringify({ scan_type: apiType, content }) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The analysis service is unavailable.");
    return data;
  }

  async function analyzeImage(type, content) {
    const response = await fetch("/api/education-chat", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", cache: "no-store", body: JSON.stringify({ question: type === "qr" ? "Analyze this QR code screenshot for scam risk." : "Analyze this screenshot for scam risk.", evidence_text: content, scan_type: "auto", image: imagePayload, language: document.documentElement.lang === "my" ? "my" : "en", stream: false }) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "The image analysis service is unavailable.");
    const assessment = data.assessment || {};
    const analysis = data.analysis || {};
    const risk = assessment.risk || ({ high: "HIGH", warning: "MEDIUM", low: "LOW" }[analysis.riskLevel] || "LOW");
    return {
      risk,
      risk_score: assessment.risk_score ?? (risk === "HIGH" ? 85 : risk === "MEDIUM" ? 55 : 18),
      confidence: assessment.confidence ?? Math.round((Number(analysis.confidence) || 0) * 100),
      category: assessment.category || analysis.riskLevel || "Screenshot review",
      reason: assessment.reason || analysis.summary || data.answer,
      indicators: assessment.indicators || analysis.warningSigns || [],
      agent_headline: analysis.summary || assessment.category || "Screenshot analysis complete",
      agent_summary: data.answer || analysis.summary || assessment.reason,
      recommended_actions: assessment.recommended_actions || analysis.recommendedActions || []
    };
  }

  function fillList(element, values, emptyText) {
    const rows = Array.isArray(values) && values.length ? values.slice(0, 3) : [emptyText];
    element.replaceChildren(...rows.map((value) => { const item = document.createElement("li"); item.textContent = value; return item; }));
  }

  function concise(value, maximum = 260) {
    const text = String(value || "").replace(/\s+/g, " ").trim();
    return text.length > maximum ? `${text.slice(0, maximum - 1).trimEnd()}…` : text;
  }

  function renderResult(result, { open = true } = {}) {
    activeResult = result;
    const risk = String(result.risk || "LOW").toUpperCase();
    const score = Math.max(0, Math.min(99, Number(result.risk_score) || (risk === "HIGH" ? 85 : risk === "MEDIUM" ? 55 : 18)));
    document.getElementById("dashboardFindingScore").textContent = `${score}%`;
    document.getElementById("dashboardFindingRisk").textContent = `${risk} RISK`;
    document.getElementById("dashboardFindingRisk").dataset.risk = risk.toLowerCase();
    document.getElementById("dashboardFindingConfidence").textContent = `${Math.max(0, Math.min(99, Number(result.confidence) || 0))}%`;
    document.getElementById("dashboardFindingHeadline").textContent = result.agent_headline || result.category || "Analysis complete";
    document.getElementById("dashboardFindingSummary").textContent = concise(result.agent_summary || result.reason || "The investigation is complete.");
    document.getElementById("dashboardFindingPattern").textContent = result.category || "No exact pattern match";
    document.getElementById("dashboardFindingReason").textContent = concise(result.reason || "Verify unexpected requests through an official channel.", 220);
    fillList(document.getElementById("dashboardFindingWarnings"), result.indicators, "No strong automated warning sign was found.");
    fillList(document.getElementById("dashboardFindingActions"), result.recommended_actions, "Verify the request independently before acting.");
    results.hidden = false;
    resultReportReadiness.sync();
    reportSubmitReadiness.sync();
    copyButton.disabled = false;
    exportButton.disabled = false;
    progress.hidden = true;
    analyzeButton.classList.add("is-complete");
    analyzeButton.dataset.resultReady = "true";
    analyzeButton.textContent = "Investigation complete";
    saveState();
    if (open) openResultsDialog();
  }

  async function runProgress(task) {
    const steps = [...progress.querySelectorAll("li")];
    steps.forEach((step) => step.classList.remove("is-complete", "is-active"));
    progress.hidden = false;
    const timers = steps.map((step, index) => window.setTimeout(() => {
      steps.slice(0, index).forEach((item) => item.classList.add("is-complete"));
      step.classList.add("is-active");
      progressLabel.textContent = step.textContent;
    }, index * 360));
    try {
      const value = await task();
      steps.forEach((step) => { step.classList.remove("is-active"); step.classList.add("is-complete"); });
      progressLabel.textContent = "Investigation complete";
      return value;
    } finally { timers.forEach(window.clearTimeout); }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (analyzeButton.dataset.resultReady === "true" && activeResult) {
      openResultsDialog();
      return;
    }
    const type = currentType();
    const content = input.value.trim();
    if (!content && !imagePayload) { setStatus("Enter suspicious content or upload evidence first.", "error"); input.focus(); return; }
    analyzeReadiness.setBusy(true);
    analyzeButton.classList.remove("is-complete");
    analyzeButton.textContent = "Analyzing...";
    results.hidden = true;
    setStatus("SafeMind is analyzing your evidence...", "pending");
    try {
      const result = await runProgress(() => imagePayload ? analyzeImage("screenshot", content) : analyzeText(type, content));
      renderResult(result);
      setStatus("Investigation complete.", "success");
      const { data } = await supabase?.auth.getSession() || {};
      if (data?.session?.user) {
        const { error: historyError } = await supabase.rpc("award_scan_credit", { scan_kind: type, scan_risk: String(result.risk || "low").toLowerCase() });
        if (!historyError) window.dispatchEvent(new CustomEvent("safemind:scan-complete", { detail: { scanType: type, risk: String(result.risk || "low").toLowerCase() } }));
      }
    } catch (error) {
      setStatus(error.message || "The investigation could not be completed. Please retry.", "error");
      analyzeButton.textContent = "Retry analysis";
    } finally { analyzeReadiness.setBusy(false); }
  });

  document.getElementById("quickScanInvestigate").addEventListener("click", () => {
    const value = quickInput.value.trim();
    resetAnalyzeButton({ clearResult: true });
    input.value = value;
    openInvestigation(detectType(value));
    if (value) form.requestSubmit();
  });
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-open-investigation], [data-investigation-type]");
    if (!trigger) return;
    event.preventDefault();
    openInvestigation(trigger.dataset.investigationType || currentType());
  });
  document.getElementById("quickScanUpload").addEventListener("click", () => { resetAnalyzeButton({ clearResult: true }); openInvestigation("message"); fileInput.click(); });
  document.getElementById("quickScanVoice").addEventListener("click", () => {
    const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!Recognition) { quickInput.placeholder = "Voice input is not supported in this browser."; return; }
    const recognition = new Recognition(); recognition.lang = document.documentElement.lang === "my" ? "my-MM" : "en-US";
    recognition.onresult = (event) => { quickInput.value = event.results[0][0].transcript; quickReadiness.sync(); saveState(); };
    recognition.start();
  });
  window.addEventListener("dashboard:sectionchange", (event) => {
    saveState();
    if (event.detail?.section === "investigation") focusMobileInvestigation();
  });
  window.addEventListener("pageshow", focusMobileInvestigation);
  form.addEventListener("change", (event) => { if (event.target.name === "dashboardScanType") { resetAnalyzeButton({ clearResult: true }); updateType(event.target.value); } });
  input.addEventListener("input", () => { resetAnalyzeButton({ clearResult: true }); saveState(); });
  quickInput.addEventListener("input", saveState);
  fileInput.addEventListener("change", () => selectFile(fileInput.files?.[0]).catch((error) => setStatus(error.message, "error")));
  document.getElementById("dashboardScanFileRemove").addEventListener("click", () => { resetAnalyzeButton({ clearResult: true }); clearFile(); setStatus(""); saveState(); });
  uploadArea.addEventListener("dragover", (event) => { event.preventDefault(); uploadArea.classList.add("is-dragging"); });
  uploadArea.addEventListener("dragleave", () => uploadArea.classList.remove("is-dragging"));
  uploadArea.addEventListener("drop", (event) => { event.preventDefault(); uploadArea.classList.remove("is-dragging"); selectFile(event.dataTransfer.files?.[0]).catch((error) => setStatus(error.message, "error")); });

  copyButton.addEventListener("click", async () => {
    const text = `${document.getElementById("dashboardFindingRisk").textContent}\n${document.getElementById("dashboardFindingHeadline").textContent}\n${document.getElementById("dashboardFindingSummary").textContent}`;
    await navigator.clipboard.writeText(text).catch(() => {}); setStatus("Result copied.", "success");
  });

  function escapeAuditText(value) {
    return String(value || "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
  }

  function auditList(values, fallback) {
    const rows = Array.isArray(values) && values.length ? values : [fallback];
    return rows.map((value) => `<li>${escapeAuditText(value)}</li>`).join("");
  }

  exportButton.addEventListener("click", () => {
    if (!activeResult) return;
    const auditWindow = window.open("", "_blank", "width=900,height=780");
    if (!auditWindow) { setStatus("Allow pop-ups to save the PDF audit.", "error"); return; }
    auditWindow.opener = null;
    const risk = String(activeResult.risk || "LOW").toUpperCase();
    const score = Math.max(0, Math.min(99, Number(activeResult.risk_score) || 0));
    const confidence = Math.max(0, Math.min(99, Number(activeResult.confidence) || 0));
    const auditId = `SM-${Date.now().toString(36).toUpperCase()}`;
    const evidence = input.value.trim().slice(0, 3000) || `[${selectedFile?.name || "Uploaded evidence"}]`;
    auditWindow.document.open();
    auditWindow.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>SafeMind Audit ${auditId}</title><style>
      @page{size:A4;margin:18mm}*{box-sizing:border-box}body{margin:0;color:#1F2937;background:#fff;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans Myanmar",sans-serif}header{display:flex;justify-content:space-between;gap:24px;padding-bottom:18px;border-bottom:3px solid #5A5D7A}h1{margin:0;font-size:26px}h2{margin:24px 0 8px;font-size:17px;color:#303247}.meta{text-align:right;color:#64748B}.risk{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:22px 0}.risk div{padding:16px;border:1px solid #E2E8F0;border-radius:12px}.risk strong{display:block;font-size:22px}.risk .${risk.toLowerCase()}{border-color:${risk === "HIGH" ? "#EF4444" : risk === "MEDIUM" ? "#F59E0B" : "#22C55E"};background:${risk === "HIGH" ? "#FEF2F2" : risk === "MEDIUM" ? "#FFFBEB" : "#F0FDF4"}}section{break-inside:avoid}.evidence{padding:14px;border:1px solid #E2E8F0;border-radius:10px;white-space:pre-wrap;overflow-wrap:anywhere}li{margin:5px 0}footer{margin-top:30px;padding-top:14px;border-top:1px solid #E2E8F0;color:#64748B;font-size:11px}.actions{margin:18px 0;padding:14px;border-radius:10px;background:#F8FAFC}.print{position:fixed;right:18px;bottom:18px;padding:11px 16px;border:0;border-radius:10px;color:#fff;background:#5A5D7A;font-weight:700}@media print{.print{display:none}}
    </style></head><body><header><div><h1>SafeMind Investigation Audit</h1><span>Explainable automated security assessment</span></div><div class="meta"><strong>${auditId}</strong><br>${escapeAuditText(new Date().toLocaleString())}</div></header>
    <main><div class="risk"><div class="${risk.toLowerCase()}"><span>Risk</span><strong>${escapeAuditText(risk)}</strong></div><div><span>Risk score</span><strong>${score}%</strong></div><div><span>Confidence</span><strong>${confidence}%</strong></div></div>
    <section><h2>Assessment</h2><strong>${escapeAuditText(activeResult.agent_headline || activeResult.category || "Investigation complete")}</strong><p>${escapeAuditText(activeResult.agent_summary || activeResult.reason || "No summary available.")}</p></section>
    <section><h2>Evidence reviewed</h2><div class="evidence">${escapeAuditText(evidence)}</div></section>
    <section><h2>Warning signs</h2><ul>${auditList(activeResult.indicators, "No strong automated warning sign was found.")}</ul></section>
    <section class="actions"><h2>Recommended actions</h2><ol>${auditList(activeResult.recommended_actions, "Verify the request independently before acting.")}</ol></section>
    <section><h2>Similar scam pattern</h2><p><strong>${escapeAuditText(activeResult.category || "No exact pattern match")}</strong><br>${escapeAuditText(activeResult.reason || "Verify unexpected requests through an official channel.")}</p></section></main>
    <footer>This audit is automated guidance, not a guarantee of safety. Verify unexpected requests through an official channel. Never include passwords, OTP codes, recovery phrases, or full payment details.</footer><button class="print" onclick="window.print()">Save as PDF</button></body></html>`);
    auditWindow.document.close();
    auditWindow.focus();
    window.setTimeout(() => auditWindow.print(), 300);
    setStatus("PDF audit is ready to save.", "success");
  });

  document.getElementById("dashboardResultsClose").addEventListener("click", closeResultsDialog);
  resultsDialog.addEventListener("click", (event) => { if (event.target === resultsDialog) closeResultsDialog(); });
  resultsDialog.addEventListener("close", () => document.body.classList.remove("modal-open"));
  reportButton.addEventListener("click", () => { closeResultsDialog(); reportDialog.showModal(); document.body.classList.add("modal-open"); });
  const closeDialog = () => { reportDialog.close(); document.body.classList.remove("modal-open"); };
  document.getElementById("investigationReportClose").addEventListener("click", closeDialog);
  reportDialog.addEventListener("click", (event) => { if (event.target === reportDialog) closeDialog(); });
  reportDialog.addEventListener("close", () => document.body.classList.remove("modal-open"));
  reportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const reportStatus = document.getElementById("investigationReportStatus");
    const { data } = await supabase.auth.getSession();
    if (!data?.session?.user) { reportStatus.textContent = "Sign in again before sending a report."; return; }
    reportSubmitReadiness.setBusy(true);
    reportStatus.textContent = "Sending report...";
    let screenshotPath = null;
    if (selectedFile && imagePayload) {
      const extension = ({ "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp" })[selectedFile.type];
      screenshotPath = `${data.session.user.id}/${crypto.randomUUID()}.${extension}`;
      const { error: uploadError } = await supabase.storage.from("report-screenshots").upload(screenshotPath, selectedFile, { contentType: selectedFile.type, cacheControl: "3600", upsert: false });
      if (uploadError) { reportSubmitReadiness.setBusy(false); reportStatus.textContent = "The screenshot could not be uploaded. Please retry."; return; }
    }
    const { error } = await supabase.from("admin_reports").insert({ reporter_id: data.session.user.id, report_type: currentType(), content: input.value.trim().slice(0, 5000) || `[${selectedFile?.name || "Uploaded evidence"}]`, notes: document.getElementById("investigationReportNotes").value.trim() || null, automated_result: activeResult, screenshot_path: screenshotPath, screenshot_name: imagePayload ? selectedFile?.name.slice(0, 255) : null, screenshot_type: imagePayload ? selectedFile?.type : null, screenshot_size: imagePayload ? selectedFile?.size : null, status: "pending" });
    if (error && screenshotPath) await supabase.storage.from("report-screenshots").remove([screenshotPath]);
    reportSubmitReadiness.setBusy(false);
    reportStatus.textContent = error ? "The report could not be sent. Please retry." : "Report sent for administrator review.";
    if (!error) window.setTimeout(closeDialog, 900);
  });

  try {
    const saved = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "null");
    const sectionController = window.SafeMindDashboardSections;
    const sectionRequestsInvestigation = sectionController?.current?.() === "investigation";
    const locationRequestsInvestigation = window.location.hash === "#investigation" || new URLSearchParams(window.location.search).get("view") === "investigation";
    if (saved) { quickInput.value = saved.quick || ""; input.value = saved.input || ""; quickReadiness.sync(); analyzeReadiness.sync(); overviewScroll = Number(saved.overviewScroll) || 0; updateType(saved.type || "message"); if (saved.result) renderResult(saved.result, { open: false }); if (sectionRequestsInvestigation || locationRequestsInvestigation || (!sectionController && saved.investigating)) openInvestigation(saved.type, true); }
    else if (window.location.hash === "#investigation" || new URLSearchParams(window.location.search).get("view") === "investigation") openInvestigation("message");
  } catch { updateType("message"); }
}
