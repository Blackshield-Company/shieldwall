// Runs the same inputs through the Python collectors and the JS port and compares results.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as R from "../src/rules.js";
import { SAMPLE } from "../src/sample.js";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const py = spawnSync("python3", ["--version"]);
const skip = py.status !== 0 ? "python3 not available" : false;

const SCRIPT = `
import json, sys
from shieldwall.collectors.ports import parse_ss, plate_from_listeners
from shieldwall.collectors.ssh import parse_ssh_log, ssh_plate, dedupe_events
from shieldwall.collectors.firewall import parse_nft_ruleset, parse_ufw_default
from shieldwall.collectors.updates import parse_apt_upgradable, updates_plate
from shieldwall.collectors.secrets import RULES
from shieldwall.config import allowlist_from_config
from shieldwall.meter import armor_meter
d = json.load(sys.stdin)
allow = allowlist_from_config({"ports": {"allow": ["22/tcp", "80/tcp", "443/tcp"]}})
out = {
  "ports": plate_from_listeners(parse_ss(d["ports"]), allow, "ss").to_dict(),
  "ssh": ssh_plate(dedupe_events(parse_ssh_log(d["ssh"])), 20, 10, "pasted log").to_dict(),
  "nft": parse_nft_ruleset(d["nft"]),
  "ufw": parse_ufw_default(d["firewall"]),
  "apt": updates_plate("apt", parse_apt_upgradable(d["updates"])).to_dict(),
  "rules": [r for r, p in RULES if any(p.search(l) for l in d["secrets"].splitlines())],
  "meter": armor_meter(["intact", "scored", "broken", "unknown", "intact"]).to_dict(),
}
print(json.dumps(out))
`;

test("JS port matches the Python rules", { skip }, () => {
  const nft = "table inet f {\n chain input { type filter hook input priority 0; policy drop; }\n chain i2 { type filter hook input priority 1; policy accept; }\n}";
  const input = { ...SAMPLE, nft };
  const res = spawnSync("python3", ["-c", SCRIPT], { cwd: repo, input: JSON.stringify(input), encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  const want = JSON.parse(res.stdout);
  const strip = (p) => ({ name: p.name, status: p.status, headline: p.headline, detail: p.detail, evidence: p.evidence, error: p.error });
  assert.deepEqual(strip(R.portsFromText(SAMPLE.ports, "22/tcp, 80/tcp, 443/tcp")), want.ports);
  assert.deepEqual(strip(R.sshFromText(SAMPLE.ssh)), want.ssh);
  assert.deepEqual(R.parseNftRuleset(nft), want.nft);
  assert.equal(R.parseUfwDefault(SAMPLE.firewall), want.ufw);
  assert.deepEqual(strip(R.updatesFromText(SAMPLE.updates)), want.apt);
  assert.deepEqual(R.scanText(SAMPLE.secrets).map((h) => h.ruleId), want.rules);
  assert.deepEqual(R.armorMeter(["intact", "scored", "broken", "unknown", "intact"]), want.meter);
});
