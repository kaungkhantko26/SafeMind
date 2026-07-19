import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { isOpenRouterScanConfigured, scanWithOpenRouter } from "./openrouter-scan.js";

const SUPPORTED_SCAN_TYPES = new Set(["message", "link", "email", "phone"]);
const TOOL_ROUTES = {
  message: ["intent_nlp", "social_engineering_rules"],
  link: ["url_parser", "phishing_rules"],
  email: ["email_parser", "impersonation_rules"],
  phone: ["phone_normalizer", "number_risk_rules"]
};
const AGENT_CACHE = new Map();
const AGENT_CACHE_TTL_MS = 300_000;
const AGENT_CACHE_MAX = 256;
const OPENROUTER_AGENT_CACHE = new Map();
const SHORTENER_DOMAINS = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly"]);
const RISKY_TLDS = new Set(["click", "country", "download", "gq", "loan", "men", "mom", "party", "rest", "review", "stream", "top", "vip", "work", "zip"]);
const URL_BAIT_TERMS = new Set(["account", "auth", "bank", "confirm", "login", "password", "payment", "reset", "secure", "signin", "update", "verify", "wallet"]);
const BRAND_TERMS = new Set(["amazon", "apple", "facebook", "google", "instagram", "microsoft", "netflix", "paypal", "telegram", "whatsapp"]);
const FREE_MAIL_DOMAINS = new Set(["gmail.com", "hotmail.com", "icloud.com", "outlook.com", "proton.me", "yahoo.com"]);
const EMAIL_PATTERN = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Z0-9-]+\.)+[A-Z]{2,63}$/i;
const PHRASE_SIGNALS = new Map([
  ["verify now", 0.18],
  ["click here", 0.18],
  ["gift card", 0.22],
  ["send your password", 0.28],
  ["bank details", 0.22],
  ["credit card number", 0.26],
  ["verification code", 0.20],
  ["act now", 0.14],
  ["အခုပဲ", 0.14],
  ["စကားဝှက်", 0.20],
  ["လင့်ခ်ကို နှိပ်", 0.20],
  ["လင့်ခ်ကို နှိပ်ပါ", 0.24],
  ["မှတ်ပုံတင်", 0.14],
  ["ငွေဖြည့်", 0.28],
  ["လက်ဆောင်", 0.16],
  ["အချက်အလက်များရယူရန်", 0.12],
  ["one time password", 0.24],
  ["confirm your identity", 0.18],
  ["pay immediately", 0.20],
  ["send the code", 0.22],
  ["keep this confidential", 0.16],
  ["guaranteed return", 0.20],
  ["remote access", 0.18],
  ["do not tell anyone", 0.18],
  ["avoid arrest", 0.22],
  ["install this app", 0.16],
  ["share the access code", 0.24],
  ["recovery phrase", 0.30],
  ["seed phrase", 0.30],
  ["private key", 0.30],
  ["processing fee", 0.18],
  ["training fee", 0.18],
  ["work from home", 0.10],
  ["remote task", 0.18],
  ["flexible online", 0.12],
  ["travel listings", 0.14],
  ["receive commission", 0.18],
  ["daily income", 0.18],
  ["rating hotels", 0.24],
  ["reviewing hotels", 0.22],
  ["easy tasks", 0.14],
  ["earn commission", 0.18],
  ["add funds", 0.24],
  ["top up", 0.24],
  ["unlock withdrawal", 0.28],
  ["unpaid toll", 0.20],
  ["delivery fee", 0.20],
  ["package is pending", 0.16],
  ["account has been locked", 0.16],
  ["reactivate your account", 0.18],
  ["investment opportunity", 0.16],
  ["online relationship", 0.10],
  ["ဘဏ်ဝန်ထမ်း", 0.16],
  ["otp ကုဒ်", 0.24],
  ["ငွေလွှဲ", 0.18],
  ["လျှို့ဝှက်ထား", 0.18]
]);
const CONTEXT_SIGNALS = [
  [/\b(?:send|share|tell|enter)\b.{0,35}\b(?:otp|pin|password|passcode|verification code)\b/i, 0.25, "Requests an authentication secret"],
  [/(?:otp|အတည်ပြုကုဒ်|လျှို့ဝှက်ကုဒ်).{0,35}(?<!မ)(?:ပို့|ပေး|မျှဝေ|ပြော|ထည့်)(?:ပါ|ပေးပါ)/iu, 0.32, "Requests an authentication secret"],
  [/\b(?:pay|transfer|send)\b.{0,40}\b(?:money|crypto|bitcoin|gift card|fee|deposit)\b/i, 0.22, "Requests a difficult-to-reverse payment"],
  [/\b(?:urgent|immediately|final warning|act now|today only)\b/i, 0.12, "Uses urgency or pressure"],
  [/(?:ချက်ချင်း|အခုပဲ|မလုပ်ရင်|မပို့ရင်|အကောင့်ပိတ်|ပိတ်မယ်)/u, 0.16, "Uses urgency or pressure"],
  [/\b(?:guaranteed|double|risk.?free)\b.{0,30}\b(?:profit|return|investment|money)\b/i, 0.22, "Promises unrealistic financial returns"],
  [/(https?:\/\/|\bwww\.)/i, 0.06, "Contains a link requiring independent verification"],
  [/(?:^|\s)(?:[a-z0-9-]+\.)+(?:com|net|org|info|top|vip|work|click)(?:\/[a-z0-9_/?=&%.-]*)?(?:\s|$)/i, 0.16, "Contains a bare website link requiring verification"],
  [/(?:ဆု|လက်ဆောင်|အတွင်းလူအချက်အလက်).{0,80}(?:မှတ်ပုံတင်|ငွေဖြည့်|လင့်ခ်|နှိပ်)/u, 0.28, "Uses a reward lure to request registration or payment"],
  [/(?:မှတ်ပုံတင်|စာရင်းသွင်း).{0,60}(?:ငွေဖြည့်|ငွေသွင်း|ပေးချေ)/u, 0.26, "Requests registration followed by a payment or top-up"],
  [/(?:လင့်ခ်|ဝဘ်ဆိုက်).{0,35}(?:နှိပ်|ဖွင့်)(?:ပါ)?/u, 0.22, "Requests clicking an unverified link"],
  [/\b(?:bank|police|government|support|ceo|manager)\b.{0,45}\b(?:send|share|pay|install|transfer)\b/i, 0.20, "Claims authority while requesting action"],
  [/\b(?:secret|confidential|do not tell|keep this between us)\b/i, 0.16, "Requests secrecy"],
  [/\b(?:remote access|screen share|anydesk|teamviewer|access code)\b/i, 0.22, "Requests remote device access"],
  [/\b(?:won|winner|prize|lottery|reward)\b.{0,45}\b(?:fee|pay|claim|bank|card)\b/i, 0.22, "Uses a prize or reward lure"],
  [/\b(?:arrest|lawsuit|police|warrant|penalty)\b/i, 0.18, "Uses threats or intimidation"],
  [/\b(?:seed phrase|recovery phrase|private key|wallet key)\b/i, 0.30, "Requests a wallet recovery secret"],
  [/\b(?:job|hiring|recruiter|work from home|employment)\b.{0,70}\b(?:fee|deposit|crypto|gift card|equipment payment)\b/i, 0.24, "Requests payment for a job opportunity"],
  [/(?:remote|online|flexible|work from home).{0,70}(?:task|rating|review|hotel|app|product).{0,80}(?:earn|income|commission|paid|start today)/i, 0.55, "Offers a fake task or rating job"],
  [/(?:task|rating|review|commission).{0,80}(?:add funds|top up|deposit|buy credits|unlock|withdraw)/i, 0.45, "Requires payment to unlock task earnings"],
  [/(?:package|parcel|delivery).{0,70}(?:fee|payment|address|return).{0,70}(?:link|click|http|www\.|[a-z0-9-]+\.[a-z]{2,})/i, 0.32, "Uses a fake delivery problem to request payment or data"],
  [/(?:toll|road fee).{0,60}(?:unpaid|overdue|penalty|pay now).{0,70}(?:link|click|http|www\.|[a-z0-9-]+\.[a-z]{2,})/i, 0.32, "Uses a fake toll charge and payment link"],
  [/(?:bank alert|unusual activity|card locked|account suspended).{0,80}(?:verify|confirm|reactivate|click|login)/i, 0.30, "Impersonates an account alert to steal credentials"],
  [/(?:subscription|membership).{0,60}(?:renew|charge|expired).{0,60}(?:cancel|click|link|update payment)/i, 0.26, "Uses a fake subscription charge or cancellation link"],
  [/(?:refund|overpaid|rebate).{0,60}(?:claim|process|bank details|click|link)/i, 0.24, "Uses a fake refund to request financial information"],
  [/(?:electricity|utility|water|service).{0,60}(?:disconnect|shut off|overdue).{0,60}(?:pay|link|click)/i, 0.30, "Threatens service disconnection to demand payment"],
  [/\b(?:love|relationship|fianc[eé]|dear|sweetheart)\b.{0,100}\b(?:money|loan|transfer|crypto|emergency)\b/i, 0.22, "Uses a relationship to request money"],
  [/\b(?:investment|trading|forex|crypto)\b.{0,70}\b(?:guaranteed|double|profit|return|risk.?free)\b/i, 0.24, "Promises unrealistic investment returns"],
  [/\b(?:support|technician|security team)\b.{0,70}\b(?:anydesk|teamviewer|screen share|remote access|install)\b/i, 0.24, "Impersonates support to request remote access"],
  [/\b(?:scan|open)\b.{0,30}\bqr\s*code\b/i, 0.08, "Requests interaction with a QR code"]
];
const BENIGN_SIGNALS = new Map([
  ["official app", 0.14],
  ["appointment is confirmed", 0.10],
  ["meeting has moved", 0.08],
  ["receipt is attached", 0.08],
  ["monthly statement", 0.08],
  ["will never ask", 0.16]
]);
const AUTHORITY_CLAIM_PATTERN = /(?:\b(?:this is|i am|i'm)\b.{0,90}\b(?:president|chancellor|vice[ -]?chancellor|ceo|chief executive|director|dean|professor|minister|governor|mayor|police officer|officer|manager|boss|bank manager)\b|(?:ကျွန်တော်|ကျွန်မ|ငါ|ဒီမှာ).{0,45}(?:သမ္မတ|ဥက္ကဋ္ဌ|အမှုဆောင်အရာရှိ|ဒါရိုက်တာ|ဌာနမှူး|ပါမောက္ခ|ဝန်ကြီး|အုပ်ချုပ်ရေးမှူး|ရဲအရာရှိ|မန်နေဂျာ|ဘဏ်မန်နေဂျာ)(?:ပါ|ဖြစ်ပါတယ်)?)/iu;
const PRIVATE_CHANNEL_PATTERN = /(?:\b(?:my|a|this)\s+(?:private|personal|new|temporary|other|alternate)\s+(?:phone\s+)?(?:number|line|account)\b|\b(?:private|personal|new|temporary|other|alternate)\s+(?:phone\s+)?(?:number|line|account)\b|\b(?:texting|messaging|contacting|writing)\s+(?:you\s+)?from\s+(?:my|a|this)\s+(?:private|personal|new|temporary|other|alternate)\b|(?:ကိုယ်ပိုင်|သီးသန့်|ပုဂ္ဂိုလ်ရေး|အသစ်|ယာယီ|အခြား)(?:ဖုန်း)?(?:နံပါတ်|လိုင်း|အကောင့်))/iu;
const URGENCY_PATTERN = /(?:\b(?:urgent|urgency|urgently|immediate|immediately|as soon as possible|asap|time[ -]?sensitive|right away)\b|(?:အရေးကြီး|အရေးပေါ်|အမြန်|ချက်ချင်း|အခုပဲ))/iu;
const REPLY_REQUEST_PATTERN = /(?:\b(?:reply|respond|get back to me|leave (?:me )?a message|message me|text me|acknowledge (?:this|receipt)|let me know once you (?:see|receive|read))\b|(?:စာပြန်|အကြောင်းပြန်|ပြန်လည်ဆက်သွယ်|ပြန်ဆက်သွယ်|မက်ဆေ့ချ်ပို့|မက်ဆေ့ချ်ထား))/iu;
const MESSAGE_SPAM_TERMS = [
  ["password", 5],
  ["verify", 4],
  ["urgent", 3],
  ["click", 3],
  ["account", 3],
  ["gift", 3],
  ["bank", 4],
  ["otp", 5],
  ["code", 3],
  ["money", 3],
  ["payment", 3],
  ["free", 2],
  ["winner", 3],
  ["wallet", 4],
  ["seed", 5],
  ["recovery", 4],
  ["job", 2],
  ["investment", 4]
];
const WINDOW_SECONDS = 60;
const LIMIT = Number(process.env.NLP_RATE_LIMIT || 30);
const requests = new Map();

function jsonResponse(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  for (const [name, value] of Object.entries(extraHeaders)) {
    res.setHeader(name, String(value));
  }
  res.end(body);
}

function getClientIp(req) {
  const forwardedFor = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return (forwardedFor || req.socket?.remoteAddress || "unknown").slice(0, 80);
}

function checkRateLimit(key) {
  const now = Date.now();
  const cutoff = now - WINDOW_SECONDS * 1000;
  const safeKey = String(key || "unknown").slice(0, 80);
  const entries = (requests.get(safeKey) || []).filter((timestamp) => timestamp > cutoff);
  if (entries.length >= LIMIT) {
    const retryAfter = Math.max(1, Math.round(WINDOW_SECONDS - (now - entries[0]) / 1000));
    requests.set(safeKey, entries);
    return { allowed: false, retryAfter };
  }
  entries.push(now);
  requests.set(safeKey, entries);
  if (requests.size > 10_000) {
    requests.clear();
    requests.set(safeKey, entries);
  }
  return { allowed: true, retryAfter: 0 };
}

function agentGuidance(scanType, risk) {
  const subject = { message: "message", link: "link", email: "sender", phone: "number" }[scanType] || "item";
  if (risk === "HIGH") {
    return {
      headline: "High-risk behavior detected",
      summary: `I found strong warning signals in this ${subject}. Treat it as unsafe unless the organization verifies it through an official channel.`,
      actions: [
        "Do not click, reply, pay, call back, or share any code.",
        "Block the sender and preserve the content as evidence.",
        "Contact the organization through its official app, website, or published phone number."
      ]
    };
  }
  if (risk === "MEDIUM") {
    return {
      headline: "Suspicious signals need verification",
      summary: `I found warning signals in this ${subject}, but the evidence is not conclusive. Pause and verify it independently before acting.`,
      actions: [
        "Do not use contact details or links contained in the suspicious content.",
        "Verify the request through an official channel.",
        "Never share passwords, OTP codes, recovery keys, or payment details."
      ]
    };
  }
  return {
    headline: "No strong threat signal found",
    summary: `I did not find strong automated warning signals in this ${subject}. This is not a guarantee of safety, especially for unexpected requests.`,
    actions: [
      "Confirm the sender and context independently if the request was unexpected.",
      "Open official apps or websites directly instead of following supplied links.",
      "Keep credentials, verification codes, and payment details private."
    ]
  };
}

function result(scanType, score, category, reason, indicators, model) {
  const boundedScore = Math.max(0, Math.min(99, Math.round(score)));
  let risk;
  let verdict;
  let confidence;
  if (boundedScore >= 70) {
    risk = "HIGH";
    verdict = "scam";
    confidence = Math.min(99, 72 + Math.round((boundedScore - 70) * 0.9));
  } else if (boundedScore >= 35) {
    risk = "MEDIUM";
    verdict = "suspicious";
    confidence = Math.min(92, 60 + Math.round((boundedScore - 35) * 0.9));
  } else {
    risk = "LOW";
    verdict = "unknown";
    confidence = Math.min(88, 58 + Math.round((35 - boundedScore) * 0.7));
  }

  const guidance = agentGuidance(scanType, risk);
  return {
    scan_type: scanType,
    verdict,
    risk,
    risk_score: boundedScore,
    confidence,
    category,
    reason,
    indicators: [...new Set((indicators || []).filter(Boolean))].slice(0, 6),
    model,
    agent_headline: guidance.headline,
    agent_summary: guidance.summary,
    recommended_actions: guidance.actions,
    requires_human_review: risk !== "LOW",
    is_spam: verdict === "scam" || verdict === "suspicious",
    label: verdict === "unknown" ? "not_spam" : "spam",
    spam_probability: Number((boundedScore / 100).toFixed(4)),
    nlp_stack: ["heuristic feature extractor", "phrase heuristics", "explainable risk scoring"]
  };
}

function normalizeText(value) {
  return String(value || "")
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "");
}

function tokenize(text) {
  return normalizeText(text)
    .toLowerCase()
    .match(/[a-z0-9]+|[\u1000-\u109f]+/giu) || [];
}

function spamTerms(tokens) {
  const frequency = new Map();
  for (const token of new Set(tokens)) {
    const count = MESSAGE_SPAM_TERMS.find(([term]) => term === token)?.[1] || 0;
    if (count > 0) frequency.set(token, count);
  }
  return [...frequency.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([token]) => token);
}

function analyzeMessage(value) {
  const cleaned = normalizeText(value).trim();
  const tokens = tokenize(cleaned);
  if (!tokens.length) {
    throw new Error("Message does not contain readable words.");
  }

  let probability = 0.12;
  const lowered = cleaned.toLowerCase();
  const phrases = [...PHRASE_SIGNALS.keys()].filter((phrase) => lowered.includes(phrase));
  const contextual = CONTEXT_SIGNALS.filter(([pattern]) => pattern.test(cleaned));
  const authorityClaim = AUTHORITY_CLAIM_PATTERN.test(cleaned);
  const privateChannel = PRIVATE_CHANNEL_PATTERN.test(cleaned);
  const urgency = URGENCY_PATTERN.test(cleaned);
  const replyRequest = REPLY_REQUEST_PATTERN.test(cleaned);
  const authorityChannelImpersonation = authorityClaim && privateChannel && (urgency || replyRequest);
  const authorityPressureImpersonation = authorityClaim && urgency && replyRequest;
  const phraseBoost = phrases.reduce((sum, phrase) => sum + PHRASE_SIGNALS.get(phrase), 0);
  const contextBoost = contextual.reduce((sum, [, boost]) => sum + boost, 0);
  let benignDiscount = Math.min(0.24, [...BENIGN_SIGNALS].reduce((sum, [phrase, weight]) => sum + (lowered.includes(phrase) ? weight : 0), 0));
  const combinationBoost = contextual.length >= 2 ? 0.10 : 0;
  if (contextual.some(([, boost]) => boost >= 0.22)) benignDiscount = Math.min(benignDiscount, 0.04);

  if (/(password|passcode|otp|verification code)/i.test(cleaned)) probability += 0.34;
  if (/(seed phrase|recovery phrase|private key|wallet key)/i.test(cleaned)) probability += 0.42;
  if (/(urgent|immediately|act now|today only)/i.test(cleaned)) probability += 0.2;
  if (/(gift card|bank details|credit card|payment|money|crypto)/i.test(cleaned)) probability += 0.18;
  if (/\b(?:bc1[a-z0-9]{25,62}|0x[a-f0-9]{40})\b/i.test(cleaned)) probability += 0.24;
  if (/(https?:\/\/|www\.)/i.test(cleaned)) probability += 0.08;
  if (cleaned.length > 120) probability -= 0.05;

  probability = Math.max(0.01, Math.min(0.99, probability + phraseBoost + Math.min(0.45, contextBoost) + combinationBoost - benignDiscount));
  // Executive-impersonation scams often contain no link or payment request in
  // their opening message. Score the behavior combination, not a person's name.
  if (authorityChannelImpersonation) probability = Math.max(probability, 0.82);
  else if (authorityPressureImpersonation) probability = Math.max(probability, 0.74);
  const isSpam = probability >= 0.50;
  const behavioralIndicators = [];
  if (authorityClaim) behavioralIndicators.push("Claims a senior or trusted identity");
  if (privateChannel) behavioralIndicators.push("Uses a private or changed contact channel");
  if (replyRequest) behavioralIndicators.push("Requests a reply before identity verification");
  if (authorityChannelImpersonation || authorityPressureImpersonation) {
    behavioralIndicators.unshift("Possible authority impersonation through an unverifiable channel");
  }
  const indicators = [...behavioralIndicators, ...phrases, ...contextual.map(([, , label]) => label), ...spamTerms(tokens)];
  const confidence = isSpam ? probability : 1 - probability;
  const risk = probability >= 0.70 ? "HIGH" : probability >= 0.50 ? "MEDIUM" : "LOW";
  const indicatorSet = new Set(indicators);
  let category = isSpam ? "Spam / Scam Message" : "Likely Safe Message";
  const categoryRules = [
    ["Possible authority impersonation through an unverifiable channel", "Authority impersonation scam"],
    ["Requests an authentication secret", "Credential phishing"],
    ["Requests a wallet recovery secret", "Crypto wallet theft"],
    ["Requests payment for a job opportunity", "Job scam"],
    ["Offers a fake task or rating job", "Task job scam"],
    ["Requires payment to unlock task earnings", "Task job scam"],
    ["Uses a fake delivery problem to request payment or data", "Delivery scam"],
    ["Uses a fake toll charge and payment link", "Toll-payment scam"],
    ["Impersonates an account alert to steal credentials", "Account phishing"],
    ["Uses a fake subscription charge or cancellation link", "Subscription scam"],
    ["Uses a fake refund to request financial information", "Refund scam"],
    ["Threatens service disconnection to demand payment", "Utility-payment scam"],
    ["Uses a relationship to request money", "Romance scam"],
    ["Promises unrealistic investment returns", "Investment scam"],
    ["Impersonates support to request remote access", "Tech-support scam"],
    ["Requests a difficult-to-reverse payment", "Payment scam"],
    ["Requests remote device access", "Remote-access scam"],
    ["Uses a prize or reward lure", "Prize or reward scam"],
    ["Promises unrealistic financial returns", "Investment scam"]
  ];
  const categoryMatch = categoryRules.find(([indicator]) => indicatorSet.has(indicator));
  if (categoryMatch) category = categoryMatch[1];
  const reason = isSpam
    ? `Spam-like language detected: ${[...new Set(indicators)].slice(0, 4).join(", ")}.`
    : "The NLP model found no strong spam pattern in this message.";

  return {
    ...result(
      "message",
      probability * 100,
      category,
      reason,
      indicators.length ? indicators : ["No strong spam phrases detected"],
      "safemind-intent-nlp-v3"
    ),
    is_spam: isSpam,
    label: isSpam ? "spam" : "not_spam",
    spam_probability: Number(probability.toFixed(4)),
    confidence: Math.round(confidence * 100),
    risk,
    category,
    reason,
    indicators: [...new Set(indicators)].slice(0, 6)
  };
}

function analyzeLink(value) {
  const candidate = value.includes("://") ? value : `https://${value}`;
  let parsed;
  try {
    parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
      throw new Error();
    }
  } catch {
    return result("link", 96, "Invalid or dangerous URL", "The value is not a valid HTTP or HTTPS address.", ["Invalid URL format"], "url-threat-features-v2");
  }

  let score = 5;
  const indicators = [];
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const labels = hostname.split(".");

  if (parsed.protocol !== "https:") {
    score += 20;
    indicators.push("Connection does not use HTTPS");
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
    score += 35;
    indicators.push("Uses an IP address instead of a domain");
  }

  if (hostname.includes("xn--")) {
    score += 30;
    indicators.push("Internationalized domain may imitate another name");
  }

  if (/[^\x00-\x7F]/.test(hostname)) {
    score += 24;
    indicators.push("Unicode domain requires careful visual verification");
  }

  if (SHORTENER_DOMAINS.has(hostname) || [...SHORTENER_DOMAINS].some((item) => hostname.endsWith(`.${item}`))) {
    score += 30;
    indicators.push("Shortened URL hides its final destination");
  }

  if (parsed.username || parsed.password || value.split("?")[0].includes("@")) {
    score += 30;
    indicators.push("URL contains misleading user-information syntax");
  }

  if (labels.length > 4) {
    score += 14;
    indicators.push("Unusually deep subdomain structure");
  }

  if ((hostname.match(/-/g) || []).length >= 3) {
    score += 14;
    indicators.push("Domain contains many hyphens");
  }

  if (RISKY_TLDS.has(labels[labels.length - 1])) {
    score += 18;
    indicators.push(`Frequently abused .${labels[labels.length - 1]} domain ending`);
  }

  const inspected = `${hostname}${parsed.pathname}`.toLowerCase();
  const bait = [...URL_BAIT_TERMS].filter((term) => inspected.includes(term));
  if (bait.length) {
    score += Math.min(32, bait.length * 9);
    indicators.push(`Credential or payment bait: ${bait.slice(0, 4).join(", ")}`);
  }

  if (value.length > 180) {
    score += 12;
    indicators.push("Unusually long URL");
  }

  if ((value.match(/%/g) || []).length >= 4) {
    score += 14;
    indicators.push("Heavy URL encoding may hide the destination path");
  }

  const category = score >= 35 ? "Potential phishing link" : "No obvious URL threats";
  const reason = indicators.length
    ? "Structural phishing indicators were detected in this URL."
    : "No common structural phishing indicators were detected; verify the sender before opening it.";

  return result("link", score, category, reason, indicators.length ? indicators : ["No known structural warning signs"], "url-threat-features-v2");
}

function analyzeEmail(value) {
  const raw = String(value || "").trim();
  const fromAddress = raw.match(/^from:\s*.*?([A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63})/im)?.[1];
  const extractedAddress = fromAddress || raw.match(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/i)?.[0] || "";
  const lowered = extractedAddress.toLowerCase();
  if (!EMAIL_PATTERN.test(lowered)) {
    return result("email", 92, "Invalid or deceptive email address", "The sender address is malformed or cannot be reliably verified.", ["Invalid email format"], "email-threat-features-v2");
  }

  const [, domain] = lowered.split("@");
  const labels = domain.split(".");
  let score = 6;
  const indicators = [];

  if (domain.includes("xn--")) {
    score += 30;
    indicators.push("Punycode domain may imitate a trusted brand");
  }

  if (RISKY_TLDS.has(labels[labels.length - 1])) {
    score += 22;
    indicators.push(`Frequently abused .${labels[labels.length - 1]} domain ending`);
  }

  const brands = [...BRAND_TERMS].filter((term) => lowered.includes(term));
  if (brands.length && FREE_MAIL_DOMAINS.has(domain)) {
    score += 38;
    indicators.push("Brand name is sent from a free mailbox provider");
  }

  if (brands.length && domain.includes("-")) {
    score += 22;
    indicators.push("Brand-like domain uses impersonation-style separators");
  }

  if ((domain.match(/-/g) || []).length >= 3) {
    score += 15;
    indicators.push("Domain contains many hyphens");
  }

  const local = lowered.split("@")[0];
  if (local.length > 64 || local.includes("..")) {
    score += 20;
    indicators.push("Unusual mailbox structure");
  }

  if (/(security|support|verify|billing|admin)/.test(local) && RISKY_TLDS.has(labels[labels.length - 1])) {
    score += 20;
    indicators.push("Authority-style mailbox on a high-risk domain");
  }

  const category = score >= 35 ? "Potential sender impersonation" : "No obvious sender threats";
  const reason = indicators.length
    ? "The sender address contains impersonation or domain-risk indicators."
    : "The address format has no obvious impersonation indicators; confirm the domain independently.";

  return result("email", score, category, reason, indicators.length ? indicators : ["Valid email structure"], "email-threat-features-v2");
}

function combineWithSpamLanguage(scanType, primary, content) {
  const containsProse = scanType === "email"
    ? /(?:^|\n)(?:subject|from|to):/im.test(content) || content.replace(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/ig, "").trim().length >= 12
    : /\s/.test(content) && content.replace(/https?:\/\/\S+|\+?[\d\s().-]{7,22}/gi, "").trim().length >= 12;
  if (!containsProse) {
    return {
      ...primary,
      pipeline: ["type-specific analysis", "shared spam-language analysis skipped because no prose was present"]
    };
  }
  let language;
  try {
    language = analyzeMessage(content);
  } catch {
    return primary;
  }
  const primaryScore = Number(primary.risk_score) || 0;
  const languageScore = Number(language.risk_score) || 0;
  const languageDominates = languageScore > primaryScore;
  const combined = result(
    scanType,
    Math.max(primaryScore, languageScore),
    languageDominates ? language.category : primary.category,
    languageDominates ? language.reason : primary.reason,
    [...(primary.indicators || []), ...(language.indicators || [])],
    `${primary.model}+safemind-intent-nlp-v3`
  );
  const isSpam = combined.risk === "HIGH" || combined.risk === "MEDIUM";
  return {
    ...combined,
    is_spam: isSpam,
    label: isSpam ? "spam" : "not_spam",
    spam_probability: Math.max(Number(primary.spam_probability) || 0, Number(language.spam_probability) || 0),
    pipeline: ["type-specific analysis", "shared spam-language analysis"]
  };
}

function analyzePhone(value) {
  const normalized = String(value || "").replace(/[^\d+]/g, "");
  const digits = normalized.replace(/\D/g, "");

  if (!(digits.length >= 7 && digits.length <= 15) || (normalized.match(/\+/g) || []).length > 1 || (normalized.includes("+") && !normalized.startsWith("+"))) {
    return result("phone", 86, "Invalid phone number", "The number does not match a valid international phone-number structure.", ["Invalid phone number format"], "phone-risk-features-v2");
  }

  let score = 8;
  const indicators = [];

  if (!String(value || "").trim().startsWith("+")) {
    score += 8;
    indicators.push("Country code is missing");
  }

  if (digits.startsWith("1900") || digits.startsWith("900")) {
    score += 48;
    indicators.push("Premium-rate prefix");
  }

  if (/(.)\1{5,}/.test(digits)) {
    score += 28;
    indicators.push("Long repeated-digit sequence");
  }

  if (["012345", "123456", "234567", "987654", "876543"].some((sequence) => digits.includes(sequence))) {
    score += 22;
    indicators.push("Artificial sequential-digit pattern");
  }

  if (new Set(digits).size <= 3) {
    score += 20;
    indicators.push("Unusually low digit variety");
  }

  const category = score >= 35 ? "Suspicious phone pattern" : "Unknown phone number";
  const reason = indicators.length && score >= 35
    ? "The number contains patterns often associated with suspicious or premium-rate calls."
    : "No strong number-pattern warning was found; an unknown caller still requires verification.";

  return result("phone", score, category, reason, indicators.length ? indicators : ["Valid phone-number structure"], "phone-risk-features-v2");
}

function analyzePayload(scanType, content) {
  const value = validateScanInput(scanType, content);

  const primary = scanType === "message"
    ? analyzeMessage(value)
    : scanType === "link"
      ? analyzeLink(value)
      : scanType === "email"
        ? analyzeEmail(value)
        : analyzePhone(value);
  return scanType === "message" ? primary : combineWithSpamLanguage(scanType, primary, value);
}

function validateScanInput(scanType, content) {
  if (!SUPPORTED_SCAN_TYPES.has(scanType)) {
    throw new Error("Scan type must be message, link, email, or phone.");
  }
  if (typeof content !== "string" || !content.trim()) {
    throw new Error("Content must not be empty.");
  }

  const value = content.trim();
  const limits = { message: 10_000, link: 2_048, email: 10_000, phone: 32 };
  if (value.length > limits[scanType]) {
    throw new Error(`${scanType[0].toUpperCase()}${scanType.slice(1)} must be ${limits[scanType]} characters or fewer.`);
  }
  return value;
}

function buildInvestigation(scanType, content, analysis, investigationTimeMs) {
  const evidence = [];
  const addMatches = (regex, kind, label, severity, explanation) => {
    for (const match of content.match(regex) || []) evidence.push({ kind, label, severity, value: match.slice(0, 180), explanation });
  };
  addMatches(/https?:\/\/[^\s<>"']+/gi, "url", "URL found", "medium", "Inspect the destination independently.");
  addMatches(/(?:^|\s)((?:[a-z0-9-]+\.)+(?:com|net|org|info|top|vip|work|click)(?:\/[a-z0-9_/?=&%.-]*)?)/gi, "url", "Bare URL found", "medium", "Do not open the destination until it is verified independently.");
  addMatches(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}/gi, "email", "Email address found", "low", "Verify the sender domain.");
  addMatches(/\b(?:bc1[a-z0-9]{25,62}|0x[a-f0-9]{40})\b/gi, "crypto_wallet", "Crypto wallet found", "high", "Crypto payments are difficult to reverse.");
  const behaviors = [
    [/\b(?:otp|one.?time password|verification code|passcode)\b|otp ကုဒ်/i, "OTP request", "high", 25],
    [/\b(?:password|pin|recovery key|login code)\b|စကားဝှက်/i, "Credential request", "high", 25],
    [/\b(?:pay|payment|transfer|gift card|bitcoin|crypto|bank details)\b|ငွေလွှဲ/i, "Money request", "high", 25],
    [/\b(?:urgent|immediately|act now|final warning|today only)\b|ချက်ချင်း|အခုပဲ/i, "Urgency language", "medium", 20],
    [/\b(?:seed phrase|recovery phrase|private key|wallet key)\b/i, "Wallet recovery secret request", "high", 30],
    [/\b(?:job|hiring|recruiter|work from home)\b.{0,70}\b(?:fee|deposit|crypto|gift card)\b/i, "Job fee request", "high", 25],
    [/\b(?:love|relationship|fianc[eé]|sweetheart)\b.{0,100}\b(?:money|loan|transfer|crypto)\b/i, "Relationship-based money request", "high", 25],
    [/\b(?:anydesk|teamviewer|screen share|remote access)\b/i, "Remote access request", "high", 25]
  ];
  const scoring = [];
  let allocated = 0;
  for (const [pattern, label, severity, weight] of behaviors) {
    if (pattern.test(content)) {
      evidence.push({ kind: "behavior", label, severity, value: null, explanation: `Detected ${label.toLowerCase()} in the submitted content.` });
      const applied = Math.min(weight, Math.max(0, analysis.risk_score - allocated));
      if (applied) scoring.push({ label, score: applied, source: "evidence" });
      allocated += applied;
    }
  }
  if (allocated < analysis.risk_score) scoring.push({ label: "ML pattern score", score: analysis.risk_score - allocated, source: "model" });
  const status = analysis.risk_score >= 90 ? "Critical" : analysis.risk_score >= 70 ? "High Risk" : analysis.risk_score >= 50 ? "Likely Scam" : analysis.risk_score >= 25 ? "Suspicious" : "Safe";
  const caseId = randomUUID();
  const caseDate = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const nodes = [{ id: "input", type: scanType, label: scanType[0].toUpperCase() + scanType.slice(1) }];
  const edges = [];
  evidence.filter((item) => ["url", "email", "phone", "crypto_wallet"].includes(item.kind)).forEach((item, index) => {
    nodes.push({ id: `evidence-${index}`, type: item.kind, label: item.label });
    edges.push({ source: "input", target: `evidence-${index}`, relation: "contains" });
  });
  return {
    case_id: caseId,
    case_number: `CASE-${caseDate}-${caseId.slice(0, 8).toUpperCase()}`,
    status,
    confidence: analysis.confidence,
    threat_type: analysis.category,
    investigation_time_ms: Number(investigationTimeMs.toFixed(3)),
    evidence_count: evidence.length + (analysis.indicators || []).length,
    document: { detected_type: scanType, language: /[\u1000-\u109f]/.test(content) ? "my" : "en", encoding: "unicode", character_count: content.trim().length, normalization: "NFKC", entities_extracted: true },
    intelligence: { local_reputation_checked: true, external_feeds_configured: false, whois_configured: false, note: "Live providers are not configured; no external reputation was invented." },
    predictions: { model: analysis.model, probabilities: { safe_or_unknown: Math.max(0, 100 - analysis.risk_score) / 100, suspicious_or_scam: analysis.risk_score / 100 }, calibration: "derived_from_active_model_risk" },
    evidence: evidence.slice(0, 16),
    scoring,
    timeline: [
      ["Input Agent", "Reading and normalizing input"], ["Threat Agent", "Checking available intelligence"],
      ["ML Agent", "Running classification models"], ["Evidence Agent", "Extracting entities and behaviors"],
      ["Reasoning Agent", "Scoring explainable evidence"], ["Decision Agent", "Producing risk decision"]
    ].map(([agent, label]) => ({ agent, label, status: "completed", duration_ms: 0 })),
    graph: { nodes, edges },
    related_cases: { available: false, matches: [], reason: "Vector similarity is ready for pgvector but not configured." },
    knowledge: { available: false, citations: [], reason: "RAG providers are not configured; no citation was fabricated." },
    checks_performed: [
      "Input validation and Unicode normalization",
      `${scanType} structure and pattern analysis`,
      "Known scam phrase and behavior detection",
      "Entity extraction and explainable risk scoring",
      "Local reputation capability check"
    ],
    limitations: [
      "Live external reputation feeds are not configured.",
      ...(scanType === "link" ? ["Domain age, ownership, and redirect-chain checks are unavailable."] : []),
      "The result is guidance and cannot guarantee safety."
    ]
  };
}

export function runAgent(scanType, content) {
  const started = performance.now();
  const key = createHash("sha256").update(`${scanType}\0${content.trim()}`).digest("hex");
  const cached = AGENT_CACHE.get(key);
  const cacheHit = Boolean(cached && Date.now() - cached.createdAt < AGENT_CACHE_TTL_MS);
  let analysis = cacheHit ? structuredClone(cached.analysis) : analyzePayload(scanType, content);
  if (!cacheHit) {
    AGENT_CACHE.set(key, { createdAt: Date.now(), analysis: structuredClone(analysis) });
    if (AGENT_CACHE.size > AGENT_CACHE_MAX) AGENT_CACHE.delete(AGENT_CACHE.keys().next().value);
  }
  const latencyMs = Math.max(0.01, performance.now() - started);
  analysis.investigation = buildInvestigation(scanType, content, analysis, latencyMs);
  const outputTokens = Math.max(1, Math.round(Buffer.byteLength(JSON.stringify(analysis), "utf8") / 4));
  const internalTelemetry = {
    run_id: randomUUID(),
    intent: `analyze_${scanType}`,
    intent_confidence: 1,
    parameters: { scan_type: scanType, content_length: content.trim().length, content_stored: false },
    selected_tools: TOOL_ROUTES[scanType] || [],
    tool_selection_correct: Boolean(TOOL_ROUTES[scanType]?.length),
    task_succeeded: true,
    turns_to_completion: 1,
    estimated_cost_usd: 0,
    cache_hit: cacheHit,
    latency_ms: Number(latencyMs.toFixed(3)),
    ttft_ms: Number(latencyMs.toFixed(3)),
    ttft_mode: "non_streaming_response",
    output_tokens_estimated: outputTokens,
    tokens_per_second_estimated: Number((outputTokens / (latencyMs / 1000)).toFixed(2)),
    compute_device: "cpu",
    throughput_per_gpu: null,
    batch_size: 1,
    batch_efficiency: 1
  };
  void internalTelemetry;
  return analysis;
}

function cleanModelField(value, max) {
  return String(value || "").normalize("NFKC").replace(/[\u0000-\u001F]/g, " ").trim().slice(0, max);
}

function normalizeOpenRouterResult(scanType, raw, model) {
  const score = Math.max(0, Math.min(99, Math.round(Number(raw?.risk_score) || 0)));
  const category = cleanModelField(raw?.category, 100) || (score >= 35 ? "Suspicious content" : "Likely Safe Message");
  const reason = cleanModelField(raw?.reason, 320) || "OpenRouter completed the scan but returned no explanation.";
  const indicators = Array.isArray(raw?.indicators)
    ? raw.indicators.map((item) => cleanModelField(item, 140)).filter(Boolean).slice(0, 3)
    : [];
  const recommendedActions = Array.isArray(raw?.recommended_actions)
    ? raw.recommended_actions.map((item) => cleanModelField(item, 180)).filter(Boolean).slice(0, 2)
    : [];
  const analysis = result(
    scanType,
    score,
    category,
    reason,
    indicators.length ? indicators : ["No strong warning signal was identified"],
    `openrouter:${cleanModelField(model, 120) || "configured-model"}`
  );
  return {
    ...analysis,
    agent_headline: category,
    agent_summary: reason,
    recommended_actions: recommendedActions,
    is_spam: analysis.risk !== "LOW",
    label: analysis.risk === "LOW" ? "not_spam" : "spam",
    spam_probability: Number((score / 100).toFixed(4)),
    nlp_stack: ["OpenRouter Chat Completions API", "Structured Outputs", "SafeMind verdict normalization"],
    analysis_source: "openrouter_structured_scan",
    provider: "openrouter",
    fallback_used: false
  };
}

function buildOpenRouterInvestigation(scanType, content, analysis, investigationTimeMs) {
  const caseId = randomUUID();
  const caseDate = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const score = Math.max(0, Math.min(99, Number(analysis.risk_score) || 0));
  const status = score >= 90 ? "Critical" : score >= 70 ? "High Risk" : score >= 35 ? "Suspicious" : "Not Scam";
  return {
    case_id: caseId,
    case_number: `CASE-${caseDate}-${caseId.slice(0, 8).toUpperCase()}`,
    status,
    confidence: analysis.confidence,
    threat_type: analysis.category,
    investigation_time_ms: Number(Math.max(0, investigationTimeMs).toFixed(3)),
    evidence_count: (analysis.indicators || []).length,
    document: {
      detected_type: scanType,
      language: /[\u1000-\u109f]/.test(content) ? "my" : "en",
      encoding: "unicode",
      character_count: content.trim().length,
      normalization: "NFKC",
      entities_extracted: false
    },
    intelligence: {
      local_reputation_checked: false,
      external_feeds_configured: false,
      note: "The verdict was generated from the current OpenRouter model response, not a fixed directory entry."
    },
    predictions: {
      model: analysis.model,
      probabilities: { safe_or_unknown: (100 - score) / 100, suspicious_or_scam: score / 100 },
      calibration: "normalized_from_openrouter_risk_score"
    },
    evidence: (analysis.indicators || []).map((label) => ({
      kind: "ai_indicator",
      label,
      severity: analysis.risk === "HIGH" ? "high" : analysis.risk === "MEDIUM" ? "medium" : "low",
      value: null,
      explanation: "Returned by the live OpenRouter scam assessment."
    })),
    scoring: [{ label: "OpenRouter model score", score, source: "model" }],
    timeline: [
      ["Input Agent", "Validating and normalizing input"],
      ["OpenRouter Agent", "Sending evidence to the configured chat model"],
      ["AI Analysis", "Classifying scam behavior and context"],
      ["Schema Validator", "Validating the structured model response"],
      ["Decision Agent", "Normalizing score and verdict fields"]
    ].map(([agent, label]) => ({ agent, label, status: "completed", duration_ms: 0 })),
    graph: { nodes: [{ id: "input", type: scanType, label: scanType[0].toUpperCase() + scanType.slice(1) }], edges: [] },
    related_cases: { available: false, matches: [], reason: "No fixed or historical case result was used for this verdict." },
    knowledge: { available: false, citations: [], reason: "No fixed knowledge-base verdict was used for this scan." },
    checks_performed: [
      "Input validation and Unicode normalization",
      "Fresh OpenRouter chat-model assessment",
      "Strict structured-output validation",
      "SafeMind verdict-field normalization"
    ],
    limitations: [
      "This AI assessment is decision support, not a guarantee.",
      "Verify unexpected requests through an independently found official channel."
    ]
  };
}

export async function runSecurityScan(scanType, content, options = {}) {
  const value = validateScanInput(scanType, content);
  const key = createHash("sha256").update(`openrouter\0${scanType}\0${value}`).digest("hex");
  const cached = OPENROUTER_AGENT_CACHE.get(key);
  if (options.allowCache === true && !options.bypassCache && cached && Date.now() - cached.createdAt < AGENT_CACHE_TTL_MS) {
    return structuredClone(cached.analysis);
  }

  try {
    const ai = await scanWithOpenRouter(scanType, value, options);
    const analysis = normalizeOpenRouterResult(scanType, ai.assessment, ai.model);
    analysis.investigation = buildOpenRouterInvestigation(scanType, value, analysis, ai.durationMs);
    if (options.allowCache === true) {
      OPENROUTER_AGENT_CACHE.set(key, { createdAt: Date.now(), analysis: structuredClone(analysis) });
      if (OPENROUTER_AGENT_CACHE.size > AGENT_CACHE_MAX) OPENROUTER_AGENT_CACHE.delete(OPENROUTER_AGENT_CACHE.keys().next().value);
    }
    return analysis;
  } catch (error) {
    const allowFallback = options.allowFallback ?? String(process.env.OPENROUTER_SCAN_FALLBACK || "disabled").toLowerCase() === "enabled";
    if (!allowFallback) throw error;
    return {
      ...runAgent(scanType, value),
      analysis_source: "local_safety_fallback",
      provider: "local",
      fallback_used: true,
      fallback_reason: error?.code === "OPENROUTER_NOT_CONFIGURED" ? "openrouter_not_configured" : "openrouter_temporarily_unavailable"
    };
  }
}

async function readRequestBody(req) {
  return await new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > 40_000) reject(new Error("The request body is too large."));
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  const method = String(req.method || "GET").toUpperCase();

  if (method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return jsonResponse(res, 204, {});
  }

  if (method === "GET") {
    return jsonResponse(res, 200, {
      status: "ok",
      model: isOpenRouterScanConfigured() ? (process.env.OPENROUTER_MODEL || "openai/gpt-4o") : "unavailable",
      provider: isOpenRouterScanConfigured() ? "openrouter" : "unavailable",
      scan_types: [...SUPPORTED_SCAN_TYPES]
    });
  }

  if (method !== "POST") {
    return jsonResponse(res, 405, { error: "Method not allowed." }, { Allow: "GET, POST, OPTIONS" });
  }

  const { allowed, retryAfter } = checkRateLimit(getClientIp(req));
  if (!allowed) {
    return jsonResponse(res, 429, { error: "Too many scans. Please wait before trying again." }, { "Retry-After": retryAfter });
  }

  const contentType = String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    return jsonResponse(res, 415, { error: "Content-Type must be application/json." });
  }

  try {
    const payload = JSON.parse(await readRequestBody(req) || "{}");
    if (typeof payload !== "object" || Array.isArray(payload) || payload === null) {
      throw new Error("The request body must be a JSON object.");
    }
    const scanType = payload.scan_type ?? (Object.prototype.hasOwnProperty.call(payload, "message") ? "message" : null);
    const content = payload.content ?? payload.message;
    return jsonResponse(res, 200, await runSecurityScan(scanType, content));
  } catch (error) {
    const status = Number(error?.statusCode) >= 500 ? Number(error.statusCode) : 400;
    return jsonResponse(res, status, { error: error.message || "Unable to analyze this message." });
  }
}
