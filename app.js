// Connects the page to the WebCyb scanner. Uses textContent everywhere so pasted text can never run as code.
const form = document.getElementById("check-form");
const $ = id => document.getElementById(id);

function fillList(el, items, render) {
  el.replaceChildren(...items.map(item => { const li = document.createElement("li"); render(li, item); return li; }));
}

form.addEventListener("submit", e => {
  e.preventDefault();
  const text = $("email").value.trim();
  $("error").hidden = true;
  if (!text) { $("error").textContent = "Please paste the email you received."; $("error").hidden = false; return; }

  const r = WebCyb.analyze(text);
  const card = $("result");
  card.className = "card result level-" + r.level.toLowerCase();
  $("badge").textContent = { High: "🚨", Medium: "⚠️", Low: "✅" }[r.level];
  $("verdict-title").textContent = { Phishing: "This email is likely PHISHING", Suspicious: "This email looks SUSPICIOUS",
                                     "Likely safe": "This email looks SAFE" }[r.verdict];
  $("risk-level").textContent = r.level;
  $("score").textContent = r.score;
  $("meter").style.width = r.score + "%";
  $("agent-reply").textContent = r.reply;

  if (r.reasons.length) {
    fillList($("reasons"), r.reasons, (li, x) => {
      const tag = document.createElement("span"); tag.className = "tag"; tag.textContent = x.category;
      li.append(tag, x.detail);
    });
  } else {
    fillList($("reasons"), ["No common phishing indicators were found."], (li, x) => { li.className = "muted"; li.textContent = x; });
  }
  fillList($("advice"), r.advice, (li, x) => { li.textContent = x; });
  card.hidden = false;
  card.scrollIntoView({ behavior: "smooth" });
});
