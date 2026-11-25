// WebCyb phishing scanner – runs entirely in the browser.
// Nothing you paste is sent anywhere or stored.
const WebCyb = (() => {
  const URGENT_WORDS = ["urgent", "immediately", "act now", "within 24 hours", "within 48 hours",
    "account suspended", "account will be closed", "final notice", "last warning", "verify now",
    "action required", "unusual activity", "suspended", "locked", "expire", "limited time",
    "legal action", "penalty"];
  const PERSONAL_INFO_WORDS = ["password", "social security", "ssn", "credit card", "card number", "cvv",
    "bank account", "pin", "login credentials", "date of birth", "verify your identity",
    "confirm your account", "update your payment", "billing information"];
  const PRIZE_WORDS = ["you have won", "you've won", "winner", "lottery", "prize", "gift card",
    "free money", "inheritance", "claim your reward", "congratulations"];
  const GENERIC_GREETINGS = ["dear customer", "dear user", "dear account holder", "dear sir/madam", "dear member"];
  const BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix", "google", "bank", "chase",
    "wellsfargo", "dhl", "fedex", "ups", "irs"];
  const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"];
  const RISKY_TLDS = [".xyz", ".top", ".click", ".zip", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".info"];
  const RISKY_ATTACHMENTS = [".exe", ".scr", ".js", ".vbs", ".bat", ".zip", ".rar", ".iso", ".html", ".docm", ".xlsm"];

  const URL_RE = /(https?:\/\/[^\s<>"')]+|www\.[^\s<>"')]+)/gi;
  const EMAIL_RE = /[\w.+-]+@(?:[\w-]+\.)+[\w-]+/gi;
  const IP_URL_RE = /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/i;

  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const find = (words, text) => words.filter(w => new RegExp("(?<![\\w])" + esc(w) + "(?![\\w])").test(text));
  const quoteList = ws => ws.slice(0, 5).map(w => `"${w}"`).join(", ");
  const title = s => s.charAt(0).toUpperCase() + s.slice(1);
  const isRealBrandDomain = (host, brand) => host === `${brand}.com` || host.endsWith(`.${brand}.com`);

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
  }

  function analyze(emailText) {
    const text = emailText.toLowerCase();
    const findings = []; // [points, category, detail]

    // 1. Suspicious links
    const urls = emailText.match(URL_RE) || [];
    for (const url of urls) {
      const full = /^http/i.test(url) ? url : "http://" + url;
      const host = hostOf(full);
      if (IP_URL_RE.test(full)) findings.push([25, "Suspicious link", `Link uses a raw IP address instead of a domain: ${url}`]);
      if (URL_SHORTENERS.some(s => host === s || host.endsWith("." + s)))
        findings.push([15, "Suspicious link", `Link uses a URL shortener that hides the real destination: ${url}`]);
      if (RISKY_TLDS.some(t => host.endsWith(t)))
        findings.push([15, "Suspicious link", `Link domain uses an extension often abused by scammers: ${host}`]);
      if (full.split("//")[1].split("/")[0].includes("@"))
        findings.push([25, "Suspicious link", `Link hides its real destination with an '@' trick: ${url}`]);
      const brand = BRANDS.find(b => host.includes(b) && !isRealBrandDomain(host, b));
      if (brand) findings.push([25, "Suspicious link", `Link pretends to be ${title(brand)} but goes to ${host}`]);
      if (/^http:\/\//i.test(url)) findings.push([5, "Suspicious link", `Link is not secure (http, not https): ${url}`]);
    }

    // 2. Urgent / threatening language
    const urgent = find(URGENT_WORDS, text);
    if (urgent.length) findings.push([Math.min(10 * urgent.length, 30), "Urgent language", "Pressure or threats: " + quoteList(urgent)]);

    // 3. Requests for personal information
    const personal = find(PERSONAL_INFO_WORDS, text);
    if (personal.length) findings.push([Math.min(15 * personal.length, 35), "Personal information request", "Asks for sensitive data: " + quoteList(personal)]);

    const prizes = find(PRIZE_WORDS, text);
    if (prizes.length) findings.push([Math.min(10 * prizes.length, 25), "Too good to be true", "Prize or reward bait: " + quoteList(prizes)]);

    // 4. Sender patterns
    const greet = find(GENERIC_GREETINGS, text);
    if (greet.length) findings.push([10, "Sender pattern", `Generic greeting ("${greet[0]}") instead of your name`]);
    for (const addr of emailText.match(EMAIL_RE) || []) {
      const domain = addr.split("@")[1].toLowerCase();
      const brand = BRANDS.find(b => domain.includes(b) && !isRealBrandDomain(domain, b));
      if (brand) findings.push([25, "Sender pattern", `Sender address imitates ${title(brand)}: ${addr}`]);
      if (/\d{3,}/.test(domain.split(".")[0])) findings.push([10, "Sender pattern", `Sender domain looks auto-generated: ${domain}`]);
    }

    const attach = RISKY_ATTACHMENTS.filter(a => new RegExp(esc(a) + "\\b").test(text));
    if (attach.length) findings.push([20, "Risky attachment", "Mentions a risky file type: " + attach.join(", ")]);

    const score = Math.min(findings.reduce((s, f) => s + f[0], 0), 100);
    const level = score >= 50 ? "High" : score >= 20 ? "Medium" : "Low";
    const verdict = { High: "Phishing", Medium: "Suspicious", Low: "Likely safe" }[level];
    const advice = {
      High: ["Do not click any links or open attachments.", "Do not reply or send any personal information.",
             "Contact the company directly using their official website or phone number.", "Report the email as phishing and delete it."],
      Medium: ["Be careful: verify the sender before taking any action.",
               "Hover over links to check where they really go before clicking.",
               "If it asks for information, contact the company through an official channel."],
      Low: ["No strong phishing signs were found, but stay alert.", "If something still feels off, verify with the sender another way."],
    }[level];
    const reasons = findings.map(([, category, detail]) => ({ category, detail }));
    return { score, level, verdict, reasons, advice, reply: agentReply(level, reasons) };
  }

  // The WebCyb agent writes a short plain-language reply from the scanner's findings.
  function agentReply(level, reasons) {
    const cats = [...new Set(reasons.map(r => r.category))];
    const plain = {
      "Suspicious link": "it contains links that don't go where they claim to",
      "Urgent language": "it tries to rush or scare you into acting quickly",
      "Personal information request": "it asks for private information like passwords or card details",
      "Too good to be true": "it promises prizes or rewards",
      "Sender pattern": "the sender doesn't look like who they say they are",
      "Risky attachment": "it mentions a file type that can carry malware",
    };
    const signs = cats.map(c => plain[c]);
    const join = a => a.length < 2 ? a.join("") : a.slice(0, -1).join(", ") + " and " + a[a.length - 1];
    if (level === "High")
      return `Hi! I checked your email and it is very likely a phishing attempt. The biggest warning signs: ${join(signs)}. ` +
             `Please don't click anything or reply. If you're worried about your account, go to the company's official website yourself or call them.`;
    if (level === "Medium")
      return `Hi! I checked your email and it looks suspicious: ${join(signs)}. ` +
             `It may be harmless, but treat it with care. Before you click or reply, confirm with the sender through a way you already trust.`;
    return signs.length
      ? `Hi! I checked your email and didn't find strong signs of phishing, although ${join(signs)}. It's probably fine, but stay alert.`
      : `Hi! I checked your email and didn't find common phishing signs. It looks safe, but if anything feels off, check with the sender another way.`;
  }

  return { analyze };
})();
