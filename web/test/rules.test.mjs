import { test } from "node:test";
import assert from "node:assert/strict";
import * as R from "../src/rules.js";
import { SAMPLE } from "../src/sample.js";

test("meter matches CLI scoring", () => {
  assert.deepEqual(R.armorMeter(["intact", "intact", "intact", "intact", "intact"]), { score: 100, label: "steel", disclaimer: R.DISCLAIMER });
  assert.equal(R.armorMeter(["intact", "scored", "unknown", "intact", "intact"]).label, "bone");
  assert.equal(R.armorMeter(["broken", "intact"]).label, "blood");
  assert.throws(() => R.armorMeter(["nope"]));
  assert.equal(R.meterPhrase({ label: "blood" }, ["broken", "broken"]), "blood / 2 plates broken");
});

test("firewall: nft, ufw, firewalld, disabled", () => {
  assert.equal(R.firewallFromText("table inet filter {\n chain input { type filter hook input priority 0; policy drop; }\n}").status, "intact");
  assert.equal(R.firewallFromText("chain input { type filter hook input priority 0; policy accept; }").status, "scored");
  assert.equal(R.firewallFromText("Status: active\nDefault: deny (incoming), allow (outgoing)").detail, "deny in");
  assert.equal(R.firewallFromText("Status: inactive").status, "broken");
  assert.equal(R.firewallFromText("running\npublic (active)\n  target: DROP\n").status, "intact");
  assert.equal(R.firewallFromText("not running").status, "broken");
  assert.equal(R.firewallFromText("").status, "unknown");
});

test("ports: ss parsing, allowlist and dedupe", () => {
  const ss = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\ntcp LISTEN 0 128 [::]:22 [::]:*\nudp UNCONN 0 0 127.0.0.1%lo:53 0.0.0.0:*\ntcp ESTAB 0 0 10.0.0.2:22 10.0.0.9:5000';
  const l = R.parseSs(ss);
  assert.equal(l.length, 3);
  assert.deepEqual(l[2], { proto: "udp", port: 53, bind: "127.0.0.1", process: "" });
  assert.equal(R.portsFromText(ss, "22/tcp, 53/udp").status, "intact");
  const bad = R.portsFromText(ss, "");
  assert.equal(bad.status, "broken");
  assert.match(bad.evidence[0], /no allowlist configured/);
  const toml = R.parseAllowlist('[ports]\nallow = [22, "443/tcp", { port = 53, proto = "udp" }]\n[ports.proto]\ntcp = [8080]');
  assert.ok(R.allows(toml, "tcp", 22) && R.allows(toml, "udp", 22) && R.allows(toml, "tcp", 443) && !R.allows(toml, "udp", 443));
  assert.ok(R.allows(toml, "udp", 53) && R.allows(toml, "tcp", 8080));
  assert.equal(R.portsFromText(ss, "99999").status, "unknown");
});

test("ssh: failed/accepted counting and thresholds", () => {
  const lines = Array.from({ length: 10 }, (_, i) => `Oct 16 03:12:${String(i).padStart(2, "0")} h sshd[1]: Failed password for root from 203.0.113.9 port ${5000 + i} ssh2`);
  assert.equal(R.sshFromText(lines.join("\n")).status, "broken");
  assert.equal(R.sshFromText(lines.slice(0, 2).join("\n")).status, "scored");
  const ok = R.sshFromText("Accepted publickey for me from 198.51.100.4 port 22 ssh2");
  assert.equal(ok.status, "intact");
  assert.equal(ok.detail, "198.51.100.4");
  assert.equal(R.parseSshLog("pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=192.0.2.1  user=root")[0].address, "192.0.2.1");
});

test("updates: apt, dnf, checkupdates", () => {
  assert.deepEqual(R.parseAptUpgradable("Listing...\nopenssl/stable 3 amd64 [upgradable from: 2]"), ["openssl"]);
  assert.equal(R.updatesFromText("Listing... Done\n").status, "intact");
  const dnf = R.updatesFromText("Last metadata expiration check: 0:01:00 ago\nkernel.x86_64  6.9.1-1.fc40  updates\n");
  assert.equal(dnf.detail, "dnf");
  assert.equal(dnf.headline, "1 pending");
  assert.equal(R.updatesFromText("linux 6.9.1-1 -> 6.9.2-1\nopenssl 3.3.0-1 -> 3.3.1-1").headline, "2 pending");
  assert.equal(R.updatesFromText("", "pacman").status, "intact");
  assert.equal(R.updatesFromText("gibberish").status, "unknown");
});

test("secrets: rule ids and lines only, never the value", () => {
  const p = R.secretsFromText(SAMPLE.secrets);
  assert.equal(p.status, "broken");
  assert.deepEqual(R.scanText(SAMPLE.secrets).map((h) => h.ruleId), ["aws-access-key", "hardcoded-secret"]);
  assert.ok(!p.evidence.join("\n").includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(!p.evidence.join("\n").includes("changeme"));
  assert.equal(R.secretsFromText("debug: true").status, "intact");
});

test("sample report gives a full checklist", () => {
  const r = R.buildReport(SAMPLE);
  assert.deepEqual(r.plates.map((p) => p.name), R.PLATE_NAMES);
  assert.deepEqual(r.plates.map((p) => p.status), ["scored", "broken", "scored", "scored", "broken"]);
  assert.equal(r.meter.score, 30);
  assert.equal(r.meter.label, "blood");
  for (const p of r.plates) assert.ok(p.advice.length > 10);
});

test("page has no network code and states the privacy promise", async () => {
  const { readFile } = await import("node:fs/promises");
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(html, /Nothing leaves your browser/);
  assert.match(html, /connect-src 'none'/);
  for (const f of ["../src/app.js", "../src/rules.js", "../src/sample.js"]) {
    const js = await readFile(new URL(f, import.meta.url), "utf8");
    assert.doesNotMatch(js, /\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|localStorage/);
  }
});
