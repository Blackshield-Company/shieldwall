// Shieldwall rule logic, ported from the Python collectors (shieldwall/collectors/*.py,
// shieldwall/meter.py, shieldwall/config.py). Pure functions over pasted text: no I/O,
// no network. Keep in step with the Python side; tests in web/test cover parity cases.

export const DISCLAIMER = "plate coverage, not a security guarantee";
export const VALID_STATUS = ["intact", "scored", "broken", "unknown"];
export const PLATE_NAMES = ["firewall", "ports", "ssh", "updates", "secrets"];

export function plate(name, status, headline, detail, evidence = [], error = null) {
  if (!VALID_STATUS.includes(status)) throw new Error(`invalid plate status: ${status}`);
  return { name, status, headline, detail, evidence: evidence.map(String), error };
}

export function unknownPlate(name, error, detail = "unreadable") {
  return plate(name, "unknown", "unknown", detail, [error], error);
}

// ---------- meter ----------
const POINTS = { intact: 20, scored: 10, broken: 0, unknown: 0 };

export function armorMeter(statuses) {
  for (const s of statuses) if (!VALID_STATUS.includes(s)) throw new Error(`invalid plate status: ${s}`);
  const score = Math.min(100, statuses.reduce((a, s) => a + POINTS[s], 0));
  let label;
  if (statuses.some((s) => s === "broken")) label = "blood";
  else if (statuses.length && statuses.every((s) => s === "intact")) label = "steel";
  else label = "bone";
  return { score, label, disclaimer: DISCLAIMER };
}

export function meterPhrase(meter, statuses) {
  const broken = statuses.filter((s) => s === "broken").length;
  if (broken) return `${meter.label} / ${broken} ${broken === 1 ? "plate" : "plates"} broken`;
  if (statuses.some((s) => s !== "intact")) return `${meter.label} / coverage worn`;
  return `${meter.label} / plates intact`;
}

// ---------- firewall ----------
const NFT_INPUT = /hook\s+input\b[^}]*?policy\s+(accept|drop|reject)/gi;

export function parseNftRuleset(text) {
  const policies = [...text.matchAll(NFT_INPUT)].map((m) => m[1].toLowerCase());
  if (!policies.length) return null;
  if (policies.every((p) => p === "drop" || p === "reject")) {
    return { backend: "nft", status: "intact", policy: policies[0], policies };
  }
  return { backend: "nft", status: "scored", policy: policies.includes("accept") ? "accept" : policies[0], policies };
}

export function parseFirewalldState(text) {
  const low = text.toLowerCase();
  if (low.includes("not running")) return "stopped";
  if (/\brunning\b/.test(low)) return "running";
  return null;
}

export function parseFirewalldTarget(text) {
  const m = /^\s*target:\s*(\S+)\s*$/im.exec(text);
  return m ? m[1] : null;
}

export function parseUfwStatus(text) {
  const m = /Status:\s*(active|inactive)/i.exec(text);
  return m ? m[1].toLowerCase() === "active" : null;
}

export function parseUfwDefault(text) {
  const m = /Default:\s*([A-Za-z]+)\s*\(incoming\)/i.exec(text);
  return m ? m[1].toLowerCase() : null;
}

function firewalldPlate(policy) {
  if (policy == null) return plate("firewall", "scored", "fwd running", "policy unknown", ["firewalld running", "default policy not read"]);
  const norm = policy.toLowerCase().replace(/^%+|%+$/g, "");
  if (["drop", "reject", "default"].includes(norm)) {
    const shown = norm === "drop" ? "drop" : "reject";
    return plate("firewall", "intact", "fwd running", `${shown} in`, ["firewalld running", `target ${shown}`]);
  }
  if (norm === "accept") return plate("firewall", "scored", "fwd running", "accept in", ["firewalld running", "target accept"]);
  return plate("firewall", "scored", "fwd running", "policy unknown", ["firewalld running", `target ${norm}`]);
}

function ufwPlate(policy) {
  if (["deny", "reject", "drop"].includes(policy)) return plate("firewall", "intact", "ufw active", `${policy} in`, ["ufw active", `default incoming ${policy}`]);
  if (["allow", "accept"].includes(policy)) return plate("firewall", "scored", "ufw active", "allow in", ["ufw active", "default incoming allow"]);
  return plate("firewall", "scored", "ufw active", "policy unknown", ["ufw active", "default policy not read"]);
}

// Pasted output of `nft list ruleset`, `firewall-cmd --state` + `--list-all`, or `ufw status verbose`.
export function firewallFromText(text) {
  if (!text || !text.trim()) return unknownPlate("firewall", "nothing pasted", "no input");
  const nft = parseNftRuleset(text);
  if (nft) {
    return plate("firewall", nft.status, "nft enabled", `${nft.policy} in`, [`nft input policy ${nft.policy}`, "policies: " + nft.policies.join(", ")]);
  }
  const disabled = [];
  const ufw = parseUfwStatus(text);
  if (ufw === true) return ufwPlate(parseUfwDefault(text));
  if (ufw === false) disabled.push("ufw inactive");
  const target = parseFirewalldTarget(text);
  const fwd = parseFirewalldState(text);
  if (fwd === "running" || (fwd === null && target)) return firewalldPlate(target);
  if (fwd === "stopped") disabled.push("firewalld not running");
  if (/^\s*table\s+\S+/m.test(text)) disabled.push("nft has no input policy");
  if (disabled.length) return plate("firewall", "broken", "disabled", "no policy", disabled);
  return unknownPlate("firewall", "firewall state unknown", "no policy");
}

// ---------- ports ----------
export function parseAllowlist(text) {
  const allow = { anyProto: new Set(), byProto: {}, configured: false };
  const add = (port, proto) => {
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`bad port: ${port}`);
    if (proto) (allow.byProto[proto] ||= new Set()).add(port);
    else allow.anyProto.add(port);
  };
  // Accepts "22, 443/tcp" or a config.toml [ports] section (allow = [...] and [ports.proto] tcp = [...]).
  const src = (text || "").replace(/#.*$/gm, "");
  let items = [];
  const allowArr = /allow\s*=\s*\[([\s\S]*?)\]/.exec(src);
  if (allowArr) {
    items = allowArr[1].match(/\{[^}]*\}|"[^"]*"|'[^']*'|[^,\s]+/g) || [];
    for (const m of src.matchAll(/^\s*(tcp|udp)\s*=\s*\[([^\]]*)\]/gim)) {
      for (const v of m[2].split(",")) if (v.trim()) { add(parseInt(v, 10), m[1].toLowerCase()); allow.configured = true; }
    }
  } else {
    items = src.split(/[\s,]+/);
  }
  for (let raw of items) {
    raw = raw.trim().replace(/^["']|["']$/g, "");
    if (!raw) continue;
    allow.configured = true;
    const pm = /\{\s*port\s*=\s*(\d+)(?:\s*,\s*proto\s*=\s*"(\w+)")?/.exec(raw);
    if (pm) { add(parseInt(pm[1], 10), pm[2] ? pm[2].toLowerCase() : null); continue; }
    const [p, proto] = raw.split("/");
    add(parseInt(p, 10), proto ? proto.trim().toLowerCase() : null);
  }
  return allow;
}

export function allows(allow, proto, port) {
  return allow.anyProto.has(port) || Boolean(allow.byProto[proto] && allow.byProto[proto].has(port));
}

export function splitAddr(local) {
  if (local.startsWith("[")) {
    const i = local.lastIndexOf("]:");
    if (i < 0) throw new Error(`bad address: ${local}`);
    return [local.slice(1, i), parseInt(local.slice(i + 2), 10)];
  }
  const i = local.lastIndexOf(":");
  if (i < 0) throw new Error(`bad address: ${local}`);
  let host = local.slice(0, i);
  if (host.includes("%")) host = host.split("%")[0];
  const port = Number(local.slice(i + 1));
  if (!Number.isInteger(port)) throw new Error(`bad address: ${local}`);
  return [host, port];
}

export function parseSs(text) {
  const found = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.toLowerCase().startsWith("netid")) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const pr = parts[0].toLowerCase();
    const state = parts[1].toUpperCase();
    let proto;
    if (pr.startsWith("tcp")) { proto = "tcp"; if (state !== "LISTEN") continue; }
    else if (pr.startsWith("udp")) proto = "udp";
    else continue;
    let host, port;
    try { [host, port] = splitAddr(parts[4]); } catch { continue; }
    let process = "";
    if (parts.length > 5) {
      const m = /\(\("([^"]+)"/.exec(parts.slice(5).join(" "));
      if (m) process = m[1];
    }
    found.push({ proto, port, bind: host, process });
  }
  return found;
}

export function dedupeListeners(list) {
  const order = [];
  const byKey = new Map();
  for (const item of list) {
    const key = `${item.proto}:${item.port}`;
    if (!byKey.has(key)) { byKey.set(key, item); order.push(key); }
    else if (!byKey.get(key).process && item.process) byKey.set(key, item);
  }
  return order.map((k) => byKey.get(k));
}

export function plateFromListeners(listeners, allow, source) {
  const unique = dedupeListeners(listeners);
  const unexpected = unique.filter((i) => !allows(allow, i.proto, i.port));
  let status, detail;
  if (unexpected.length) { status = "broken"; detail = `:${unexpected[0].port} ?`; }
  else if (unique.length) { status = "intact"; detail = `:${unique[0].port} ${unique[0].process || "ok"}`; }
  else { status = "intact"; detail = "none"; }
  const evidence = [];
  if (!allow.configured && unique.length) evidence.push("no allowlist configured; every listener is unexpected");
  for (const i of unique) {
    evidence.push(`${i.proto} :${i.port} ${i.bind} ${i.process || "-"} ${allows(allow, i.proto, i.port) ? "allow" : "not in allowlist"}`);
  }
  if (!unique.length) evidence.push(`no listening sockets (${source})`);
  evidence.push(`source: ${source}`);
  return plate("ports", status, `${unique.length} listen`, detail, evidence);
}

export function portsFromText(text, allowText = "") {
  if (!text || !text.trim()) return unknownPlate("ports", "nothing pasted", "no sockets");
  let allow;
  try { allow = parseAllowlist(allowText); } catch (e) { return unknownPlate("ports", `allowlist: ${e.message}`, "bad allowlist"); }
  return plateFromListeners(parseSs(text), allow, "ss");
}

// ---------- ssh ----------
const SSH_PATTERNS = [
  [/Accepted\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(\S+)\s+port\s+\d+/i, "accepted"],
  [/Failed\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(\S+)\s+port\s+\d+/i, "failed"],
  [/Invalid user\s+\S+\s+from\s+(\S+)/i, "failed"],
  [/authentication failure;.*rhost=(\S+)/i, "failed"],
];

export function parseSshLog(text) {
  const events = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line === "-- No entries --") continue;
    let kind = null, addr = null;
    for (const [re, name] of SSH_PATTERNS) {
      const m = re.exec(line);
      if (m) { kind = name; addr = m[1].replace(/:+$/, ""); break; }
    }
    if (!kind || !addr) continue;
    const iso = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)/.exec(line);
    const sys = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/.exec(line);
    events.push({ kind, address: addr, when: iso ? iso[1] : sys ? sys[1] : "" });
  }
  return events;
}

export function dedupeEvents(events) {
  const seen = new Set();
  return events.filter((e) => {
    const k = `${e.when}|${e.kind}|${e.address}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function sshPlate(events, lastN = 20, failBroken = 10, source = "pasted log") {
  const win = lastN > 0 ? events.slice(-lastN) : events;
  const accepted = win.filter((e) => e.kind === "accepted").length;
  const failed = win.filter((e) => e.kind === "failed").length;
  const status = failed >= failBroken ? "broken" : failed > 0 ? "scored" : "intact";
  let detail = "no events";
  if (win.length) { const a = win[win.length - 1].address; detail = a.length <= 14 ? a : "see log"; }
  const evidence = [`accepted: ${accepted}`, `failed: ${failed}`, `source: ${source}`];
  for (const e of win) evidence.push(`${e.when ? e.when + " " : ""}${e.kind} ${e.address}`.trim());
  return plate("ssh", status, `${failed} failed`, detail, evidence);
}

export function sshFromText(text, lastN = 20, failBroken = 10) {
  if (!text || !text.trim()) return unknownPlate("ssh", "nothing pasted", "no log");
  return sshPlate(dedupeEvents(parseSshLog(text)), Math.max(1, lastN), Math.max(1, failBroken));
}

// ---------- updates ----------
export function parseAptUpgradable(text) {
  const names = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^(Listing|WARNING|E:|W:)/.test(line)) continue;
    const token = line.split(/\s+/)[0];
    if (!token.includes("/") && !line.includes("[upgradable")) continue;
    names.push(token.split("/")[0]);
  }
  return names;
}

export function parseDnfCheckUpdate(text, returncode) {
  if (returncode === 0) return [];
  if (returncode !== 100) return null;
  const names = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.toLowerCase().startsWith("last metadata")) continue;
    if (line.endsWith(":") || line.startsWith("Obsoleting")) continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 3 && parts[0].includes(".")) names.push(parts[0]);
  }
  return names;
}

export function parseCheckupdates(text, returncode) {
  if (returncode === 2) return [];
  if (returncode !== 0) return null;
  const names = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("::")) continue;
    names.push(line.split(/\s+/)[0]);
  }
  return names;
}

export function updatesPlate(backend, names) {
  const count = names.length;
  const evidence = [`${count} pending via ${backend}`, ...names.slice(0, 8)];
  if (count > 8) evidence.push(`${count - 8} more`);
  return plate("updates", count === 0 ? "intact" : "scored", `${count} pending`, backend, evidence);
}

// backend: "apt" | "dnf" | "pacman" | "auto". Pasted text has no exit code, so an
// empty paste for dnf/pacman means "nothing pending" (exit 0 / exit 2).
export function updatesFromText(text, backend = "auto") {
  if (text == null) return unknownPlate("updates", "nothing pasted", "no tool");
  const body = text.trim();
  if (backend === "auto") {
    if (/^Listing|\[upgradable from/m.test(body)) backend = "apt";
    else if (/^\S+\.(x86_64|aarch64|noarch|i686)\s+\S+\s+\S+/m.test(body)) backend = "dnf";
    else if (/^\S+\s+\S+\s+->\s+\S+/m.test(body)) backend = "pacman";
    else if (!body) return unknownPlate("updates", "nothing pasted", "no tool");
    else return unknownPlate("updates", "could not tell apt, dnf or checkupdates output apart", "no tool");
  }
  if (backend === "apt") return updatesPlate("apt", parseAptUpgradable(body));
  if (backend === "dnf") return updatesPlate("dnf", parseDnfCheckUpdate(body, body ? 100 : 0));
  if (backend === "pacman") return updatesPlate("pacman", parseCheckupdates(body, body ? 0 : 2));
  return unknownPlate("updates", `unknown backend ${backend}`, "no tool");
}

// ---------- secrets ----------
export const SECRET_RULES = [
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["private-key", /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["github-pat", /\bghp_[A-Za-z0-9]{36}\b/],
  ["slack-token", /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/],
  ["hardcoded-secret", /\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"][^'"]{8,}['"]/i],
];

// Same as scan_file: first matching line per rule, rule id and line only (never the secret).
export function scanText(text, path = "pasted") {
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (const [ruleId, re] of SECRET_RULES) {
    const idx = lines.findIndex((l) => re.test(l));
    if (idx >= 0) hits.push({ path, ruleId, line: idx + 1 });
  }
  return hits;
}

export function secretsPlate(hits, root = "pasted", source = "builtin") {
  const count = hits.length;
  const evidence = hits.slice(0, 50).map((h) => (h.line ? `${h.path}:${h.line} ${h.ruleId}` : `${h.path} ${h.ruleId}`));
  if (count > 50) evidence.push(`${count - 50} more hits`);
  if (count === 0) evidence.push(`no hits in ${root}`);
  evidence.push(`scanner: ${source}`);
  return plate("secrets", count ? "broken" : "intact", `${count} hits`, root.slice(0, 14) || source, evidence);
}

export function secretsFromText(text) {
  if (!text || !text.trim()) return unknownPlate("secrets", "nothing pasted", "no input");
  return secretsPlate(scanText(text));
}

// ---------- checklist ----------
const ADVICE = {
  firewall: {
    broken: "Turn a firewall on with a default-deny incoming policy (ufw default deny incoming && ufw enable, or an nft input chain with policy drop).",
    scored: "Change the default incoming policy from accept/allow to drop or deny, then allow only what you serve.",
    unknown: "Paste `sudo nft list ruleset`, `sudo ufw status verbose`, or `firewall-cmd --state` plus `firewall-cmd --list-all`.",
    intact: "Default-deny incoming is in place. Review allowed services now and then.",
  },
  ports: {
    broken: "Close or firewall listeners you don't expect, or add the ones you do expect to the allowlist. Bind internal services to 127.0.0.1.",
    unknown: "Paste `ss -tulpn` (or `ss -H -tulpn`).",
    intact: "Every listener is on your allowlist.",
  },
  ssh: {
    broken: "Many failed logins: disable password auth (PasswordAuthentication no), use keys, consider fail2ban or sshguard, and move SSH off the open internet.",
    scored: "Some failed logins. Check the sources and prefer key-only auth.",
    unknown: "Paste `journalctl -u ssh -u sshd --no-pager -n 200` or the tail of /var/log/auth.log.",
    intact: "No failed logins in the window.",
  },
  updates: {
    scored: "Install pending updates (apt upgrade, dnf upgrade, or pacman -Syu) and reboot if the kernel changed.",
    unknown: "Paste `apt list --upgradable`, `dnf check-update`, or `checkupdates`.",
    intact: "No pending updates.",
  },
  secrets: {
    broken: "Rotate every credential that matched, then remove it from the file and from git history. Load secrets from the environment or a secret store.",
    unknown: "Paste a config, compose file or .env to scan it for leaked keys.",
    intact: "No known secret patterns found in what you pasted.",
  },
};

export function adviceFor(p) {
  const a = ADVICE[p.name] || {};
  return a[p.status] || a.unknown || "";
}

export function buildReport(input = {}) {
  const plates = [
    firewallFromText(input.firewall || ""),
    portsFromText(input.ports || "", input.allow || ""),
    sshFromText(input.ssh || "", input.lastN ?? 20, input.failBroken ?? 10),
    updatesFromText(input.updates || "", input.updatesBackend || "auto"),
    secretsFromText(input.secrets || ""),
  ];
  const statuses = plates.map((p) => p.status);
  const meter = armorMeter(statuses);
  return {
    read_only: true,
    disclaimer: DISCLAIMER,
    meter,
    phrase: meterPhrase(meter, statuses),
    plates: plates.map((p) => ({ ...p, advice: adviceFor(p) })),
  };
}
