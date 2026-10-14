const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sw = require("../shieldwall.js");

const NFT_DROP = `
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}
`;

const NFT_ACCEPT = `
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
}
`;

const NFT_MIXED = `
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain input_extra {
		type filter hook input priority filter; policy accept;
	}
}
`;

const FIREWALLD_DROP = `
public (active)
  target: DROP
  interfaces: eth0
  services: ssh
`;

const FIREWALLD_ACCEPT = `
public (active)
  target: ACCEPT
`;

const FIREWALLD_DEFAULT = `
public (active)
  target: default
`;

const UFW_VERBOSE_DENY = `
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
`;

const UFW_VERBOSE_ALLOW = `
Status: active
Default: allow (incoming), allow (outgoing), deny (routed)
`;

const SS_TEXT = `
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0      511                *:443             *:*    users:(("caddy",pid=9,fd=8))
udp   UNCONN 0      0      0.0.0.0%virbr0:53         0.0.0.0:*    users:(("dnsmasq",pid=2,fd=5))
`;

const PROC_TCP = `
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
`;

const PROC_TCP6 = `
  sl  local_address                         rem_address                         st tx_queue rx_queue
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000
`;

const PROC_UDP = `
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2 0000000000000000
   1: 00000000:0045 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 9 2 0000000000000000
`;

const JOURNAL = `
2026-10-12T10:15:01+0000 host sshd[123]: Accepted publickey for notausername from 192.0.2.10 port 54321 ssh2
2026-10-12T10:16:02+0000 host sshd[124]: Failed password for invalid user admin from 198.51.100.20 port 22 ssh2
2026-10-12T10:17:03+0000 host sshd[125]: Invalid user guest from 203.0.113.5
2026-10-12T10:18:04+0000 host sshd[126]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.8
`;

const AUTH = `
Oct 12 10:15:01 host sshd[123]: Accepted password for notausername from 192.0.2.10 port 22 ssh2
Oct 12 10:16:02 host sshd[124]: Failed password for user from 198.51.100.20 port 22 ssh2
`;

const APT_PENDING = `
WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
bash/stable 5.2-1 amd64 [upgradable from: 5.1-1]
openssl/stable 3.0.13-1 amd64 [upgradable from: 3.0.12-1]
`;

const DNF_PENDING = `
Last metadata expiration check: 1 day ago
bash.x86_64      5.2.26-1   updates
openssl.x86_64   3.0.13-1   updates
`;

const PAC_PENDING = `
bash 5.2.26-1 -> 5.2.26-2
`;

const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB = "ghp_" + "a".repeat(36);
const PASSWORD = "example-secret-value";
const PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----";

test("meter matches plate points and labels", () => {
  const steel = sw.armorMeter(["intact", "intact", "intact", "intact", "intact"]);
  assert.equal(steel.score, 100);
  assert.equal(steel.label, "steel");
  assert.equal(steel.disclaimer, sw.DISCLAIMER);
  assert.equal(sw.DISCLAIMER, "plate coverage, not a security guarantee");
  const scored = sw.armorMeter(["scored", "scored", "scored", "scored", "scored"]);
  assert.equal(scored.score, 50);
  assert.equal(scored.label, "bone");
  const mixed = sw.armorMeter(["intact", "intact", "intact", "intact", "unknown"]);
  assert.equal(mixed.score, 80);
  assert.equal(mixed.label, "bone");
  assert.notEqual(mixed.label, "steel");
  const broken = sw.armorMeter(["intact", "broken", "scored", "scored", "intact"]);
  assert.equal(broken.score, 60);
  assert.equal(broken.label, "blood");
  const high = sw.armorMeter(["intact", "intact", "intact", "intact", "broken"]);
  assert.equal(high.score, 80);
  assert.equal(high.label, "blood");
  assert.match(sw.meterPhrase(high, ["intact", "intact", "intact", "intact", "broken"]), /plate broken/);
  const unknown = sw.armorMeter(["unknown", "unknown", "unknown", "unknown", "unknown"]);
  assert.equal(unknown.score, 0);
  assert.equal(unknown.label, "bone");
  assert.equal(sw.POINTS.unknown, 0);
  assert.equal(sw.POINTS.intact, 20);
  assert.equal(sw.POINTS.scored, 10);
  assert.equal(sw.POINTS.broken, 0);
  const empty = sw.armorMeter([]);
  assert.equal(empty.score, 0);
  assert.equal(empty.label, "bone");
  assert.equal(sw.meterPhrase(empty, []), "bone / plates intact");
  assert.throws(() => sw.armorMeter(["healthy"]), /invalid plate status/);
  const plural = sw.armorMeter(["broken", "broken", "intact", "intact", "intact"]);
  assert.match(sw.meterPhrase(plural, ["broken", "broken", "intact", "intact", "intact"]), /2 plates broken/);
  assert.equal(sw.meterPhrase(steel, ["intact", "intact", "intact", "intact", "intact"]), "steel / plates intact");
  assert.equal(sw.meterPhrase(scored, ["scored", "scored", "scored", "scored", "scored"]), "bone / coverage worn");
});

test("firewall parsers agree on sample rulesets", () => {
  const drop = sw.parseNftRuleset(NFT_DROP);
  assert.equal(drop.status, "intact");
  assert.equal(drop.policy, "drop");
  assert.deepEqual(drop.policies, ["drop"]);
  assert.equal(sw.parseNftRuleset(NFT_ACCEPT).status, "scored");
  const mixed = sw.parseNftRuleset(NFT_MIXED);
  assert.equal(mixed.status, "scored");
  assert.equal(mixed.policy, "accept");
  assert.equal(sw.parseNftRuleset(""), null);
  assert.equal(sw.parseFirewalldState("running\n"), "running");
  assert.equal(sw.parseFirewalldState("not running\n"), "stopped");
  assert.equal(sw.parseFirewalldTarget(FIREWALLD_DROP), "DROP");
  assert.equal(sw.parseFirewalldTarget(FIREWALLD_ACCEPT), "ACCEPT");
  assert.equal(sw.parseFirewalldTarget(FIREWALLD_DEFAULT), "default");
  assert.equal(sw.parseUfwStatus("Status: inactive\n"), false);
  assert.equal(sw.parseUfwStatus(UFW_VERBOSE_DENY), true);
  assert.equal(sw.parseUfwDefault(UFW_VERBOSE_DENY), "deny");
  assert.equal(sw.parseUfwDefault(UFW_VERBOSE_ALLOW), "allow");
});

test("firewall paste uses collector status rules", () => {
  const drop = sw.firewallFromText(NFT_DROP);
  assert.equal(drop.status, "intact");
  assert.equal(drop.detail, "drop in");
  assert.equal(drop.error, null);
  assert.deepEqual(drop.evidence, ["nft input policy drop", "policies: drop"]);
  assert.equal(sw.firewallFromText(NFT_ACCEPT).status, "scored");
  const mixed = sw.firewallFromText(NFT_MIXED);
  assert.equal(mixed.status, "scored");
  assert.equal(mixed.evidence[1], "policies: drop, accept");
  assert.equal(sw.firewallFromText("Operation not permitted (you must be root)").status, "unknown");
  assert.equal(sw.firewallFromText("Operation not permitted (you must be root)").error, "nft: permission denied");
  const fwd = sw.firewallFromText("running\n" + FIREWALLD_DROP);
  assert.equal(fwd.status, "intact");
  assert.deepEqual(fwd.evidence, ["firewalld running", "target drop"]);
  assert.equal(sw.firewallFromText("running\n" + FIREWALLD_ACCEPT).status, "scored");
  const fallback = sw.firewallFromText("running\n" + FIREWALLD_DEFAULT);
  assert.equal(fallback.status, "intact");
  assert.equal(fallback.detail, "reject in");
  const stopped = sw.firewallFromText("not running\n");
  assert.equal(stopped.status, "broken");
  assert.deepEqual(stopped.evidence, ["firewalld not running"]);
  const deny = sw.firewallFromText(UFW_VERBOSE_DENY);
  assert.equal(deny.status, "intact");
  assert.match(deny.detail, /deny/);
  assert.equal(sw.firewallFromText(UFW_VERBOSE_ALLOW).status, "scored");
  assert.equal(sw.firewallFromText(UFW_VERBOSE_ALLOW).detail, "allow in");
  const inactive = sw.firewallFromText("Status: inactive\n");
  assert.equal(inactive.status, "broken");
  assert.deepEqual(inactive.evidence, ["ufw inactive"]);
  assert.equal(sw.firewallFromText("ERROR: You need to be root to run this script").status, "unknown");
  const missing = sw.firewallFromText("   ");
  assert.equal(missing.status, "unknown");
  assert.match(missing.error, /no firewall tool/);
  const both = sw.firewallFromText("permission denied\nStatus: inactive\n");
  assert.equal(both.status, "unknown");
  assert.equal(sw.firewallFromText("Status: active\n").status, "scored");
  assert.equal(sw.firewallFromText("Status: active\n").detail, "policy unknown");
});

test("ports parsers and allowlist match sample sockets", () => {
  const found = sw.parseSs(SS_TEXT);
  const ports = new Set(found.map((item) => item.proto + ":" + item.port + ":" + item.process));
  assert.equal(ports.has("tcp:22:sshd"), true);
  assert.equal(ports.has("tcp:443:caddy"), true);
  assert.equal(ports.has("udp:53:dnsmasq"), true);
  assert.equal(sw.decodeProcIp("0100007F"), "127.0.0.1");
  assert.equal(sw.decodeProcIp("00000000"), "0.0.0.0");
  assert.equal(sw.decodeProcIp("00000000000000000000000001000000"), "::1");
  const tcp = sw.parseProcNet(PROC_TCP, "tcp");
  assert.deepEqual(
    tcp.map((item) => item.port + " " + item.bind).sort(),
    ["22 0.0.0.0", "631 127.0.0.1"]
  );
  const tcp6 = sw.parseProcNet(PROC_TCP6, "tcp6");
  assert.equal(tcp6[0].port, 443);
  assert.equal(tcp6[0].bind, "::");
  assert.equal(tcp6[0].proto, "tcp");
  assert.deepEqual(
    sw.parseProcNet(PROC_UDP, "udp").map((item) => item.port),
    [53]
  );
  const unexpected = sw.plateFromListeners(sw.parseSs(SS_TEXT), sw.parseAllowlist("22"), "ss");
  assert.equal(unexpected.status, "broken");
  assert.equal(unexpected.headline, "3 listen");
  assert.equal(unexpected.detail, ":443 ?");
  assert.deepEqual(unexpected.evidence, [
    "tcp :22 0.0.0.0 sshd allow",
    "tcp :443 * caddy not in allowlist",
    "udp :53 0.0.0.0 dnsmasq not in allowlist",
    "source: ss",
  ]);
  const allowed = sw.portsFromText(SS_TEXT, "22, 443, 53/udp");
  assert.equal(allowed.status, "intact");
  const proto = sw.parseAllowlist("22/tcp, 53/udp");
  assert.equal(sw.allows(proto, "tcp", 22), true);
  assert.equal(sw.allows(proto, "udp", 22), false);
  assert.equal(sw.allows(proto, "udp", 53), true);
  assert.equal(sw.allows(proto, "tcp", 53), false);
  const open = sw.plateFromListeners(sw.parseSs(SS_TEXT), sw.parseAllowlist(""), "ss");
  assert.equal(open.status, "broken");
  assert.equal(open.evidence[0], "no allowlist configured; every listener is unexpected");
  const quiet = sw.plateFromListeners([], sw.parseAllowlist("22"), "ss");
  assert.equal(quiet.status, "intact");
  assert.equal(quiet.detail, "none");
  const proc = sw.portsFromText(PROC_TCP + PROC_TCP6 + PROC_UDP, "22, 443, 53/udp");
  assert.equal(proc.status, "broken");
  assert.equal(proc.evidence.indexOf("source: proc") !== -1, true);
  assert.match(proc.evidence.join("\n"), /:631/);
  assert.match(proc.evidence.join("\n"), /not in allowlist/);
  assert.equal(sw.portsFromText("", "22").status, "unknown");
  assert.equal(sw.portsFromText("permission denied", "").status, "unknown");
  assert.notEqual(sw.portsFromText("permission denied", "").status, "intact");
});

test("ssh log samples hide usernames and score failures", () => {
  const events = sw.parseSshLog(JOURNAL);
  assert.equal(events.length, 4);
  assert.equal(events[0].kind, "accepted");
  assert.equal(events[0].address, "192.0.2.10");
  assert.equal(events[1].kind, "failed");
  assert.equal(events[1].address, "198.51.100.20");
  assert.equal(events[2].address, "203.0.113.5");
  assert.equal(events[3].address, "192.0.2.8");
  const blob = events.map((event) => event.kind + " " + event.address).join(" ");
  assert.equal(blob.includes("notausername"), false);
  assert.equal(blob.includes("admin"), false);
  const auth = sw.parseSshLog(AUTH);
  assert.equal(auth[0].when, "Oct 12 10:15:01");
  assert.equal(auth[1].kind, "failed");
  assert.equal(auth[1].address, "198.51.100.20");
  const many = sw.parseSshLog(
    Array.from({ length: 12 }, (_, index) => {
      return "2026-10-12T10:00:" + String(index).padStart(2, "0") + "+0000 host sshd[1]: Failed password for user from 192.0.2.10 port 22 ssh2";
    }).join("\n")
  );
  const window = sw.sshPlate(many, 5, 10, "journal");
  assert.equal(window.status, "scored");
  assert.equal(window.headline, "5 failed");
  assert.equal(sw.sshPlate(many, 20, 10, "journal").status, "broken");
  assert.equal(sw.sshPlate(sw.parseSshLog(""), 20, 10, "journal").status, "intact");
  const plate = sw.sshFromText(JOURNAL);
  assert.equal(plate.status, "scored");
  assert.equal(plate.headline, "3 failed");
  assert.equal(plate.detail, "192.0.2.8");
  const joined = plate.evidence.join("\n");
  assert.match(joined, /192\.0\.2\.10/);
  assert.match(joined, /198\.51\.100\.20/);
  assert.equal(joined.includes("notausername"), false);
  assert.equal(joined.includes("Accepted publickey for"), false);
  assert.equal(joined.includes("admin"), false);
  assert.equal(joined.includes("guest"), false);
  const authPlate = sw.sshFromText(AUTH);
  assert.equal(authPlate.status, "scored");
  assert.equal(authPlate.evidence.indexOf("source: /var/log/auth.log") !== -1, true);
  assert.equal(authPlate.evidence.join("\n").includes("notausername"), false);
  const denied = sw.sshFromText("Hint: You are currently not seeing messages from other users and the system.");
  assert.equal(denied.status, "unknown");
  assert.notEqual(denied.status, "intact");
  const missing = sw.sshFromText("");
  assert.equal(missing.status, "unknown");
  assert.match(missing.error, /no ssh log/);
  assert.deepEqual(sw.journalArgv("ssh").slice(0, 4), ["journalctl", "-u", "ssh", "-o"]);
  assert.equal(sw.journalArgv("sshd").indexOf("short-iso") !== -1, true);
  assert.throws(() => sw.journalArgv("ssh;id"), /unsupported journal unit/);
  assert.equal(sw.sshFromText("-- No entries --").status, "intact");
});

test("update parsers agree on apt dnf and pacman samples", () => {
  assert.deepEqual(sw.parseAptUpgradable(APT_PENDING), ["bash", "openssl"]);
  assert.deepEqual(sw.parseAptUpgradable("Listing...\n"), []);
  assert.deepEqual(sw.parseDnfCheckUpdate(DNF_PENDING, 100), ["bash.x86_64", "openssl.x86_64"]);
  assert.deepEqual(sw.parseDnfCheckUpdate("Last metadata expiration check: now\n", 0), []);
  assert.equal(sw.parseDnfCheckUpdate("Error: lock\n", 1), null);
  assert.deepEqual(sw.parseCheckupdates(PAC_PENDING, 0), ["bash"]);
  assert.deepEqual(sw.parseCheckupdates("", 2), []);
  assert.equal(sw.parseCheckupdates("error\n", 1), null);
  const apt = sw.updatesFromText(APT_PENDING);
  assert.equal(apt.status, "scored");
  assert.equal(apt.detail, "apt");
  assert.equal(apt.headline, "2 pending");
  assert.deepEqual(apt.evidence, ["2 pending via apt", "bash", "openssl"]);
  assert.equal(sw.updatesFromText("Listing...\n").status, "intact");
  const dnf = sw.updatesFromText(DNF_PENDING);
  assert.equal(dnf.status, "scored");
  assert.equal(dnf.detail, "dnf");
  const pac = sw.updatesFromText(PAC_PENDING);
  assert.equal(pac.status, "scored");
  assert.equal(pac.detail, "pacman");
  assert.equal(sw.updatesFromText("exit: 2").status, "intact");
  assert.equal(sw.updatesFromText("exit: 2").detail, "pacman");
  const missing = sw.updatesFromText("");
  assert.equal(missing.status, "unknown");
  assert.match(missing.error, /no package manager/);
  const denied = sw.updatesFromText("E: Could not open lock file - open (13: Permission denied)");
  assert.equal(denied.status, "unknown");
  assert.equal(denied.error, "apt: permission denied");
  const locked = sw.updatesFromText("E: Could not get lock");
  assert.equal(locked.status, "unknown");
  assert.equal(locked.error, "apt exited 100");
  const extra = [];
  for (var i = 0; i < 9; i++) extra.push("pkg" + i + ".x86_64 1 repo");
  const many = sw.updatesFromText("Last metadata expiration check: now\n" + extra.join("\n") + "\n");
  assert.equal(many.evidence[many.evidence.length - 1], "1 more");
  for (const group of Object.values(sw.COMMANDS)) {
    for (const argv of group) {
      assert.equal(argv.indexOf("install"), -1);
      assert.equal(argv.indexOf("upgrade"), -1);
    }
  }
});

test("secret rules report id and line only", () => {
  const keyPlate = sw.secretsFromText("# " + EXAMPLE_KEY + "\n", "app.py");
  assert.equal(keyPlate.evidence[0], "app.py:1 aws-access-key");
  assert.equal(JSON.stringify(keyPlate).includes(EXAMPLE_KEY), false);
  const both = sw.scanText("token = '" + EXAMPLE_KEY + "'\n", "ok.py");
  assert.equal(both[0].ruleId, "aws-access-key");
  assert.equal(both[0].line, 1);
  assert.equal(both[1].ruleId, "hardcoded-secret");
  assert.equal(JSON.stringify(both).includes(EXAMPLE_KEY), false);
  const env = sw.secretsFromText('password = "' + PASSWORD + '"\n', ".env");
  assert.equal(env.status, "broken");
  assert.equal(env.evidence[0], ".env:1 hardcoded-secret");
  assert.equal(JSON.stringify(env).includes(PASSWORD), false);
  const key = sw.secretsFromText(PRIVATE + "\nnot-a-real-key\n", "id_ed25519");
  assert.equal(key.evidence[0], "id_ed25519:1 private-key");
  assert.equal(JSON.stringify(key).includes(PRIVATE), false);
  assert.equal(JSON.stringify(key).includes("not-a-real-key"), false);
  const gh = sw.scanText(GITHUB + "\n", "token.txt");
  assert.equal(gh[0].ruleId, "github-pat");
  assert.equal(JSON.stringify(gh).includes(GITHUB), false);
  const slack = sw.scanText("xoxb-1234567890abcdef\n", "slack.txt");
  assert.equal(slack[0].ruleId, "slack-token");
  assert.equal(slack[0].line, 1);
  assert.equal(sw.scanText("xoxb-123\n", "slack.txt").length, 0);
  assert.equal(sw.scanText('password = "short"\n', "a.txt").length, 0);
  assert.equal(sw.scanText("ghp_" + "a".repeat(35) + "\n", "a.txt").length, 0);
  assert.equal(sw.scanText("hello\n", "a.txt").length, 0);
  const quiet = sw.secretsFromText("print('ok')\n", "main.py");
  assert.equal(quiet.status, "intact");
  assert.equal(quiet.evidence[0], "no hits in main.py");
  const empty = sw.secretsFromText("  ", "app.py");
  assert.equal(empty.status, "unknown");
  assert.notEqual(empty.status, "intact");
  const dup = sw.scanText(EXAMPLE_KEY + "\n" + EXAMPLE_KEY + "\n", "two.txt");
  assert.equal(dup.length, 1);
  assert.equal(dup[0].line, 1);
  const payload = {
    findings: [
      {
        path: "src/app.py",
        rule_id: "aws-access-key",
        line: 4,
        secret: EXAMPLE_KEY,
        match: "supersecretvalue",
        value: PASSWORD,
      },
    ],
  };
  const hits = sw.parseSecretsweep(JSON.stringify(payload));
  assert.equal(hits[0].path, "src/app.py");
  assert.equal(hits[0].ruleId, "aws-access-key");
  assert.equal(hits[0].line, 4);
  const swept = sw.secretsFromText(JSON.stringify(payload), "/tmp/proj");
  assert.equal(swept.status, "broken");
  assert.equal(swept.evidence[0], "src/app.py:4 aws-access-key");
  assert.equal(JSON.stringify(swept).includes(EXAMPLE_KEY), false);
  assert.equal(JSON.stringify(swept).includes("supersecretvalue"), false);
  assert.equal(JSON.stringify(swept).includes(PASSWORD), false);
  const alt = sw.parseSecretsweep(JSON.stringify([{ file: "a.env", rule: "github-pat", snippet: GITHUB }]));
  assert.equal(alt[0].path, "a.env");
  assert.equal(alt[0].ruleId, "github-pat");
  assert.equal(alt[0].line, null);
  assert.equal((alt[0].path + alt[0].ruleId).includes(GITHUB), false);
  assert.throws(() => sw.parseSecretsweep("not-json"));
  assert.equal(sw.secretsFromText("not-json", "note.txt").status, "intact");
  assert.deepEqual(sw.secretsweepArgv("my path; echo injected"), [
    "secretsweep",
    "scan",
    "my path; echo injected",
    "--format",
    "json",
  ]);
  const skipped = sw.scanText(EXAMPLE_KEY + "\n", "shot.png");
  assert.equal(skipped.length, 0);
  const overflow = [];
  for (var n = 0; n < 51; n++) overflow.push({ path: "f" + n, ruleId: "aws-access-key", line: n + 1 });
  const capped = sw.secretsPlate(overflow, "root", "builtin", false);
  assert.equal(capped.evidence.length, 52);
  assert.equal(capped.evidence[50], "1 more hits");
  assert.equal(capped.evidence[51], "scanner: builtin");
});

test("evaluate builds the cli json shape and never emits secret values", () => {
  const empty = sw.evaluate({});
  assert.deepEqual(Object.keys(empty), ["host", "read_only", "disclaimer", "meter", "plates"]);
  assert.deepEqual(Object.keys(empty.meter), ["score", "label", "disclaimer"]);
  assert.deepEqual(empty.plates.map((plate) => plate.name), sw.PLATE_NAMES);
  assert.equal(empty.host, "local");
  assert.equal(empty.read_only, true);
  assert.equal(empty.disclaimer, sw.DISCLAIMER);
  assert.equal(empty.meter.score, 0);
  assert.equal(empty.meter.label, "bone");
  for (const plate of empty.plates) {
    assert.equal(plate.status, "unknown");
    assert.deepEqual(Object.keys(plate), ["name", "status", "headline", "detail", "evidence", "error"]);
    assert.notEqual(plate.status, "intact");
  }
  const report = sw.evaluate({
    firewall: NFT_DROP,
    ports: SS_TEXT,
    allow: "22, 443, 53/udp",
    ssh: JOURNAL,
    updates: "Listing...\n",
    secrets: "token = '" + EXAMPLE_KEY + "'\n",
    secretsPath: "ok.py",
    host: "box",
  });
  assert.equal(report.host, "box");
  assert.equal(report.plates[0].status, "intact");
  assert.equal(report.plates[1].status, "intact");
  assert.equal(report.plates[2].status, "scored");
  assert.equal(report.plates[3].status, "intact");
  assert.equal(report.plates[4].status, "broken");
  assert.equal(report.meter.label, "blood");
  assert.equal(report.meter.score, 70);
  const dumped = sw.formatJson(report);
  assert.equal(dumped.endsWith("\n"), true);
  assert.equal(dumped.includes(EXAMPLE_KEY), false);
  assert.equal(JSON.parse(dumped).read_only, true);
  assert.deepEqual(sw.COMMANDS.ports[0], ["ss", "-H", "-tulpn"]);
  assert.deepEqual(sw.COMMANDS.firewall[0], ["nft", "list", "ruleset"]);
  assert.deepEqual(sw.COMMANDS.updates[2], ["checkupdates"]);
  assert.deepEqual(sw.AUTH_LOG_PATHS, ["/var/log/auth.log", "/var/log/secure"]);
});

test("page is local, labeled, and lists the collector commands", () => {
  const html = fs.readFileSync(path.join(__dirname, "../index.html"), "utf8");
  assert.match(html, /Runs in your browser\. Nothing leaves this page\./);
  assert.match(html, /Plate coverage, not a security guarantee\./);
  assert.match(html, /prefers-reduced-motion/);
  assert.match(html, /shieldwall\.js/);
  assert.match(html, /Blob/);
  assert.match(html, /Download JSON/);
  assert.equal(/\bfetch\s*\(/.test(html), false);
  assert.equal(html.includes("https://"), false);
  assert.equal(html.includes("http://"), false);
  assert.match(html, /ss -H -tulpn/);
  assert.match(html, /nft list ruleset/);
  assert.match(html, /firewall-cmd --state/);
  assert.match(html, /firewall-cmd --list-all/);
  assert.match(html, /ufw status verbose/);
  assert.match(html, /journalctl -u ssh -o short-iso -n 400 --no-pager/);
  assert.match(html, /journalctl -u sshd -o short-iso -n 400 --no-pager/);
  assert.match(html, /apt list --upgradable/);
  assert.match(html, /dnf check-update/);
  assert.match(html, /checkupdates/);
  assert.match(html, /\/var\/log\/auth\.log/);
  assert.match(html, /\/var\/log\/secure/);
  assert.match(html, /for="allow"/);
  assert.match(html, /for="out-firewall"/);
  assert.match(html, /for="out-ports"/);
  assert.match(html, /for="out-ssh"/);
  assert.match(html, /for="out-updates"/);
  assert.match(html, /for="out-secrets"/);
  assert.match(html, /#8b0000/);
  assert.match(html, /#8c9ca8/);
  assert.match(html, /#e8dcc4/);
  assert.match(html, /#0c0c0e/);
});
