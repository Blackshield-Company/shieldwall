import { buildReport } from "./rules.js";
import { SAMPLE } from "./sample.js";

const form = document.getElementById("audit");
const out = document.getElementById("result");

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function render(report) {
  document.getElementById("score").textContent = String(report.meter.score);
  document.getElementById("phrase").textContent = report.phrase;
  document.getElementById("disclaimer").textContent = report.disclaimer;
  const list = document.getElementById("plates");
  list.replaceChildren();
  for (const p of report.plates) {
    const li = el("li", `plate ${p.status}`);
    const h = el("h3");
    h.append(el("span", null, p.name), el("span", "badge", p.status), el("span", "hint", `${p.headline} \u00b7 ${p.detail}`));
    li.append(h, el("p", "advice", p.advice), el("pre", "evidence", p.evidence.join("\n")));
    list.append(li);
  }
  out.hidden = false;
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(form).entries());
  render(buildReport(data));
});
document.getElementById("sample").addEventListener("click", () => {
  for (const [k, v] of Object.entries(SAMPLE)) form.elements[k].value = v;
  form.requestSubmit();
});
form.addEventListener("reset", () => { out.hidden = true; });
// /#sample opens the page with the sample filled in (handy for demos and screenshots).
if (location.hash === "#sample") document.getElementById("sample").click();
