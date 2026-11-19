/* QR Shield – decision support for QR codes. Vanilla JS, no backend, memory-only history. */
"use strict";

/* ================= 1. CONFIG ================= */
// NOTE: With the spec's scoring (http=2 + shortener=2 + words), the suspicious sample
// scores 6 and is therefore "Dangerous". Edit SAMPLES.suspicious or THRESHOLDS to change this.
const SAMPLES = {
  safe: "https://www.wikipedia.org/",
  suspicious: "http://bit.ly/secure-login-verify?user=reward",
  dangerous: "upi://pay?pa=fraudster@upi&pn=Unknown%20Payee&tn=Scan%20to%20receive%20your%20refund"
};
const THRESHOLDS = { suspicious: 1, dangerous: 4 };
const SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"];
const SUSPICIOUS_TLDS = ["xyz", "top", "buzz", "click", "loan", "work", "gq", "tk"];
const SUSPICIOUS_WORDS = ["verify", "urgent", "reward", "login", "password", "otp", "refund", "kyc", "winner"];
// brand: look-alike keywords + official domains
const BRANDS = [
  { name: "Google", keys: ["google"], official: ["google.com", "google.co.in"] },
  { name: "Amazon", keys: ["amazon"], official: ["amazon.com", "amazon.in"] },
  { name: "Flipkart", keys: ["flipkart"], official: ["flipkart.com"] },
  { name: "Paytm", keys: ["paytm"], official: ["paytm.com"] },
  { name: "PhonePe", keys: ["phonepe"], official: ["phonepe.com"] },
  { name: "Google Pay", keys: ["googlepay", "gpay"], official: ["pay.google.com", "gpay.app.goo.gl"] },
  { name: "SBI", keys: ["sbi"], official: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"], shortKey: true },
  { name: "HDFC Bank", keys: ["hdfcbank", "hdfc"], official: ["hdfcbank.com"] },
  { name: "ICICI Bank", keys: ["icicibank", "icici"], official: ["icicibank.com"] },
  { name: "Axis Bank", keys: ["axisbank"], official: ["axisbank.com"] }
];
const EXPECTED_PAYEES = ["demo store", "trusted merchant", "official payee"];
const UPI_RECEIVE_RE = /\b(receive|refund|cashback|win|prize|claim|reward)\b|get money/i;
const ADVICE = {
  safe: "No obvious warning signs were detected. Still check the website address and recipient details before entering personal or payment information.",
  suspicious: "Do not enter passwords, OTPs, card details, or UPI PINs. Verify the sender or website through an official app or website before continuing.",
  dangerous: "Do not open this link or approve any payment. If this appeared in a message, verify it independently and report or block the sender if appropriate.",
  unknown: "This QR type is not automatically analyzed. Check the content carefully before opening it, sharing information, or making a payment."
};
const LABELS = { safe: "Safe", suspicious: "Suspicious", dangerous: "Dangerous", unknown: "Unknown / Review" };

/* ================= 2. PARSING ================= */
function detectType(text) {
  const t = text.trim().toLowerCase();
  if (t.startsWith("http://") || t.startsWith("https://")) return "url";
  if (t.startsWith("upi://")) return "upi";
  return "other";
}

function parseUrl(text) {
  try {
    const u = new URL(text.trim());
    const authority = text.trim().replace(/^https?:\/\//i, "").split(/[\/?#]/)[0];
    return { ok: true, u, host: u.hostname.toLowerCase(), authority };
  } catch { return { ok: false }; }
}

function parseUpi(text) {
  const query = text.trim().split("?")[1] || "";
  const p = new URLSearchParams(query);
  return { vpa: p.get("pa") || "", name: p.get("pn") || "", amount: p.get("am") || "", note: p.get("tn") || "" };
}

// Number of labels in the registrable domain (handles co.in style endings simply)
function registrableLen(parts) {
  const sld = ["co", "com", "org", "net", "ac", "gov", "edu"];
  return parts.length >= 3 && parts[parts.length - 1].length === 2 && sld.includes(parts[parts.length - 2]) ? 3 : 2;
}

/* ================= 3. RISK RULES ================= */
const flag = (rule, points, why) => ({ rule, points, why });

function matchedWords(text) {
  let decoded = text;
  try { decoded = decodeURIComponent(text); } catch { /* keep raw */ }
  return SUSPICIOUS_WORDS.filter(w => new RegExp("\\b" + w + "\\b", "i").test(decoded));
}

function urlFlags(text, info) {
  const f = [], { u, host, authority } = info;
  const parts = host.split(".");
  if (SHORTENERS.some(d => host === d || host.endsWith("." + d)))
    f.push(flag("Shortened link", 2, "The real destination website is hidden behind a link-shortening service."));
  if (u.protocol === "http:")
    f.push(flag("HTTP instead of HTTPS", 2, "The website connection is not encrypted."));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host))
    f.push(flag("IP address instead of domain", 2, "The link uses a raw IP address instead of a normal website domain."));

  const flat = host.replace(/-/g, "");
  const fake = BRANDS.find(b => {
    const mentions = b.keys.some(k => b.shortKey ? parts.join(".").split(/[.-]/).includes(k) : flat.includes(k));
    const official = b.official.some(d => host === d || host.endsWith("." + d));
    return mentions && !official;
  });
  if (fake) f.push(flag("Look-alike domain", 3, `The domain may imitate a trusted brand (${fake.name}).`));

  const words = matchedWords(text);
  if (words.length)
    f.push(flag("Suspicious words", words.length >= 2 ? 2 : 1, `The content contains pressure or credential-related words (${words.join(", ")}).`));

  if (SUSPICIOUS_TLDS.includes(parts[parts.length - 1]))
    f.push(flag("Suspicious TLD", 2, "This domain extension is commonly associated with risky or low-trust websites."));
  if (authority.includes("@"))
    f.push(flag("@ symbol in URL", 2, "An @ symbol can hide the actual destination website from the visible URL."));
  if (parts.length - registrableLen(parts) >= 3 || text.trim().length > 120)
    f.push(flag("Too many subdomains or very long URL", 1, "The URL has many subdomains or is unusually long, which can make it harder to inspect."));
  if (host.includes("xn--"))
    f.push(flag("Punycode / look-alike characters", 3, "The domain uses Punycode, which can imitate familiar website names using similar-looking characters."));
  return f;
}

function upiFlags(text, d) {
  const f = [];
  const words = matchedWords(text);
  if (words.length)
    f.push(flag("Suspicious words", words.length >= 2 ? 2 : 1, `The content contains pressure or credential-related words (${words.join(", ")}).`));
  if (UPI_RECEIVE_RE.test(d.name) || UPI_RECEIVE_RE.test(d.note))
    f.push(flag("UPI asks you to receive money", 4, "A genuine incoming payment does not require you to scan a QR code or enter a UPI PIN."));
  if (!EXPECTED_PAYEES.includes(d.name.trim().toLowerCase()))
    f.push(flag("UPI payee-name mismatch", 3, "The payee name shown in the UPI link does not match the expected recipient."));
  return f;
}

/* ================= 4. ANALYZER ================= */
function analyze(text) {
  const type = detectType(text);
  const base = { text, type, flags: [], details: [], score: 0 };
  if (type === "url") {
    const info = parseUrl(text);
    if (!info.ok) return { ...base, type: "other", verdict: "unknown", typeLabel: "Unknown / Review (malformed link)" };
    const { u } = info;
    base.details = [["Full URL", u.href], ["Protocol", u.protocol.replace(":", "")], ["Domain", info.host],
      ["Path / query", (u.pathname + u.search) === "/" ? "None" : u.pathname + u.search]];
    base.flags = urlFlags(text, info);
    base.typeLabel = "Web URL";
  } else if (type === "upi") {
    const d = parseUpi(text);
    base.details = [["Payee address (VPA)", d.vpa || "Not provided"], ["Payee name", d.name || "Not provided"],
      ["Amount", d.amount || "Not specified"], ["Transaction note", d.note || "None"]];
    base.flags = upiFlags(text, d);
    base.typeLabel = "UPI payment link";
  } else {
    return { ...base, verdict: "unknown", typeLabel: "Unknown / Review" };
  }
  base.score = base.flags.reduce((s, x) => s + x.points, 0);
  base.verdict = base.score >= THRESHOLDS.dangerous ? "dangerous" : base.score >= THRESHOLDS.suspicious ? "suspicious" : "safe";
  return base;
}

/* ================= 5. RENDERING (textContent only -> no XSS) ================= */
const $ = id => document.getElementById(id);
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function renderResult(r) {
  const panel = $("result"), body = $("result-body");
  panel.dataset.verdict = r.verdict;
  body.replaceChildren();

  const unk = r.verdict === "unknown";
  const strip = el("div", "verdict-strip");
  const gauge = el("div", "gauge");
  gauge.style.setProperty("--p", Math.min(r.score, 10) * 10 + "%");
  gauge.append(el("b", "", unk ? "?" : String(r.score)), el("small", "", unk ? "review" : "points"));
  const info = el("div", "vs-info");
  info.append(el("span", "badge big " + r.verdict, LABELS[r.verdict]),
    el("div", "score", unk ? "Manual review needed" : `Risk score: ${r.score} point${r.score === 1 ? "" : "s"}`),
    el("div", "hint", "Detected content type: " + r.typeLabel));
  strip.append(gauge, info);
  body.append(strip);

  body.append(el("h4", "", "Decoded content"), el("div", "mono", r.text));

  if (r.details.length) {
    const dl = el("dl", "details");
    r.details.forEach(([k, v]) => dl.append(el("dt", "", k), el("dd", "", v)));
    body.append(dl);
  }

  if (r.verdict !== "unknown") {
    body.append(el("h4", "", "Triggered reasons"));
    if (!r.flags.length) body.append(el("p", "hint", "No risk rules were triggered."));
    else {
      const ul = el("ul", "reasons");
      r.flags.forEach(f => {
        const li = el("li"), s = el("strong", "", f.rule);
        s.append(el("span", "", `+${f.points} point${f.points === 1 ? "" : "s"}`));
        li.append(s, el("p", "", f.why));
        ul.append(li);
      });
      body.append(ul);
    }
  }

  body.append(el("div", "advice", "Recommended action: " + ADVICE[r.verdict]));

  // Opening a link is always an explicit, confirmed user action.
  if (r.type === "url" && r.details.length) {
    const b = el("button", "btn", "Open link (at your own risk)");
    b.style.marginTop = "12px";
    b.addEventListener("click", () => {
      if (confirm("Open this link in a new tab?\n\n" + r.text)) window.open(r.text.trim(), "_blank", "noopener,noreferrer");
    });
    body.append(b);
  }
}

function showEmpty() {
  $("result").dataset.verdict = "empty";
  const e = el("div", "empty-state");
  e.append(el("div", "big", "🔍"), el("p", "", "No result yet. Upload an image, scan with the camera, paste text, or try a sample."));
  $("result-body").replaceChildren(e);
}

/* ================= 6. HISTORY (memory only) ================= */
const history = [];
function renderHistory() {
  const tb = $("hist-body");
  tb.replaceChildren();
  history.forEach(h => {
    const tr = el("tr");
    const verdictCell = el("td"); verdictCell.append(el("span", "badge " + h.verdict, LABELS[h.verdict]));
    const short = h.text.length > 70 ? h.text.slice(0, 70) + "…" : h.text;
    tr.append(el("td", "", h.time), el("td", "", h.method), el("td", "", h.typeLabel), verdictCell,
      el("td", "", h.verdict === "unknown" ? "–" : String(h.score)), el("td", "", short));
    tb.append(tr);
  });
  $("hist-empty").hidden = history.length > 0;
}

/* ================= 7. MAIN FLOW ================= */
function handleContent(text, method) {
  $("input-error").textContent = "";
  if (!text || !text.trim()) { $("input-error").textContent = "Nothing to analyze. Enter or scan some QR content first."; return; }
  $("result").dataset.verdict = "empty";
  $("result-body").replaceChildren(el("p", "loading", "Analyzing content…"));
  setTimeout(() => {
    const r = analyze(text.trim());
    renderResult(r);
    history.unshift({ time: new Date().toLocaleTimeString(), method, typeLabel: r.typeLabel, verdict: r.verdict, score: r.score, text: r.text });
    renderHistory();
    $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }, 250);
}

/* ================= 8. INPUT METHODS ================= */
// Upload image
$("file-input").addEventListener("change", async e => {
  const file = e.target.files[0];
  if (!file) return;
  if (!/^image\/(png|jpeg)$/.test(file.type)) { $("input-error").textContent = "Please choose a JPG or PNG image."; return; }
  $("input-error").textContent = "";
  try {
    const scanner = new Html5Qrcode("file-reader");
    const text = await scanner.scanFile(file, false);
    handleContent(text, "Uploaded image");
  } catch {
    $("input-error").textContent = "No QR code was found in this image. Try a clearer, closer, well-lit picture.";
  }
  e.target.value = "";
});

// Live camera
let camScanner = null, camRunning = false;
const camMsg = t => { $("cam-msg").textContent = t; };
function setCamUi(on) { camRunning = on; $("cam-start").disabled = on; $("cam-stop").disabled = !on; }

async function stopCamera() {
  if (!camScanner || !camRunning) return;
  try { await camScanner.stop(); camScanner.clear(); } catch { /* already stopped */ }
  setCamUi(false);
}

$("cam-start").addEventListener("click", async () => {
  $("input-error").textContent = "";
  camMsg("Requesting camera permission…");
  setCamUi(true);
  try {
    camScanner = new Html5Qrcode("reader");
    await camScanner.start({ facingMode: "environment" }, { fps: 10, qrbox: { width: 220, height: 220 } },
      async text => { await stopCamera(); camMsg("QR code detected. Camera stopped."); handleContent(text, "Live camera"); },
      () => { /* per-frame "not found" is normal */ });
    camMsg("Point the camera at a QR code.");
  } catch (err) {
    setCamUi(false);
    const m = String(err);
    if (/NotAllowed|Permission|denied/i.test(m)) camMsg("Camera permission was denied. Allow camera access in your browser settings and try again.");
    else if (/NotFound|no camera|Requested device/i.test(m)) camMsg("No camera was found on this device. Try uploading an image instead.");
    else camMsg("Could not start the camera. Make sure the page is opened over HTTPS or localhost.");
  }
});
$("cam-stop").addEventListener("click", async () => { await stopCamera(); camMsg("Camera stopped."); });

// Paste text
$("paste-btn").addEventListener("click", () => handleContent($("paste-text").value, "Pasted text"));

// Samples
document.querySelectorAll("[data-sample]").forEach(b =>
  b.addEventListener("click", () => handleContent(SAMPLES[b.dataset.sample], "Sample")));

// Clear history
$("clear-btn").addEventListener("click", () => { history.length = 0; renderHistory(); });

/* Button ripple effect (visual only) */
document.addEventListener("click", e => {
  const b = e.target.closest(".btn");
  if (!b || b.disabled) return;
  const r = b.getBoundingClientRect(), d = Math.max(r.width, r.height), s = document.createElement("span");
  s.className = "ripple";
  s.style.cssText = `width:${d}px;height:${d}px;left:${e.clientX - r.left - d / 2}px;top:${e.clientY - r.top - d / 2}px`;
  b.appendChild(s);
  setTimeout(() => s.remove(), 650);
});

/* ================= 9. INIT ================= */
showEmpty();
renderHistory();

/* ================= 10. THEME + DEMO LOGIN ================= */
// Client-side demo only: credentials live in this file, so this is NOT real security.
const DEMO_USER = { name: "admin", pass: "shield123" };

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("qrs_theme", t); } catch { /* storage unavailable */ }
  document.querySelectorAll(".theme-toggle").forEach(b => { b.textContent = t === "dark" ? "☀️ Light" : "🌙 Dark"; });
}
setTheme(document.documentElement.dataset.theme === "dark" ? "dark" : "light");
document.querySelectorAll(".theme-toggle").forEach(b =>
  b.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark")));

function showApp(on) { $("login").hidden = on; $("app").hidden = !on; }
let signedIn = false;
try { signedIn = sessionStorage.getItem("qrs_auth") === "1"; } catch { /* ignore */ }
showApp(signedIn);

$("login-form").addEventListener("submit", e => {
  e.preventDefault();
  if ($("login-user").value.trim() === DEMO_USER.name && $("login-pass").value === DEMO_USER.pass) {
    try { sessionStorage.setItem("qrs_auth", "1"); } catch { /* ignore */ }
    $("login-error").textContent = "";
    $("login-pass").value = "";
    showApp(true);
    window.scrollTo(0, 0);
  } else {
    $("login-error").textContent = "Incorrect username or password. Try the demo login shown below.";
  }
});

$("logout-btn").addEventListener("click", async () => {
  await stopCamera();
  try { sessionStorage.removeItem("qrs_auth"); } catch { /* ignore */ }
  history.length = 0; renderHistory(); showEmpty();
  showApp(false);
});

// Fill the demo credentials with one click
$("demo-fill").addEventListener("click", () => {
  $("login-user").value = DEMO_USER.name;
  $("login-pass").value = DEMO_USER.pass;
  $("login-error").textContent = "";
  $("login-form").querySelector("button[type=submit]").focus();
});