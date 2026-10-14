(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.Shieldwall = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var DISCLAIMER = "plate coverage, not a security guarantee";
  var VALID_STATUS = ["intact", "scored", "broken", "unknown"];
  var PLATE_NAMES = ["firewall", "ports", "ssh", "updates", "secrets"];
  var POINTS = { intact: 20, scored: 10, broken: 0, unknown: 0 };
  var HEX = {
    blood: "#8b0000",
    steel: "#8c9ca8",
    bone: "#e8dcc4",
    void: "#0c0c0e",
  };
  var STATUS_COLOR = {
    intact: "steel",
    scored: "bone",
    broken: "blood",
    unknown: "bone",
  };
  var DENY_MARKERS = [
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "you need to be root",
    "access denied",
    "insufficient privileges",
    "not privileged",
    "a password is required",
    "not seeing messages from other users",
  ];
  var AUTH_LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"];
  var PROC_PATHS = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"];
  var JOURNAL_UNITS = ["ssh", "sshd"];
  var SKIP_EXT = {
    ".a": true,
    ".bz2": true,
    ".class": true,
    ".gif": true,
    ".gz": true,
    ".jar": true,
    ".jpeg": true,
    ".jpg": true,
    ".mp3": true,
    ".mp4": true,
    ".o": true,
    ".pdf": true,
    ".png": true,
    ".pyc": true,
    ".so": true,
    ".wasm": true,
    ".webp": true,
    ".woff": true,
    ".woff2": true,
    ".xz": true,
    ".zip": true,
  };
  var MAX_BYTES = 1000000;
  var RULES = [
    ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
    ["private-key", /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/],
    ["github-pat", /\bghp_[A-Za-z0-9]{36}\b/],
    ["slack-token", /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/],
    ["hardcoded-secret", /\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"][^'"]{8,}['"]/i],
  ];

  function journalArgv(unit) {
    if (JOURNAL_UNITS.indexOf(unit) === -1) {
      throw new Error("unsupported journal unit");
    }
    return ["journalctl", "-u", unit, "-o", "short-iso", "-n", "400", "--no-pager"];
  }

  function secretsweepArgv(path) {
    if (typeof path !== "string" || !path || path.indexOf("\0") !== -1) {
      throw new Error("invalid scan path");
    }
    return ["secretsweep", "scan", path, "--format", "json"];
  }

  var COMMANDS = {
    firewall: [
      ["nft", "list", "ruleset"],
      ["firewall-cmd", "--state"],
      ["firewall-cmd", "--list-all"],
      ["ufw", "status"],
      ["ufw", "status", "verbose"],
    ],
    ports: [["ss", "-H", "-tulpn"]],
    ssh: [journalArgv("ssh"), journalArgv("sshd")],
    updates: [
      ["apt", "list", "--upgradable"],
      ["dnf", "check-update"],
      ["checkupdates"],
    ],
  };

  function formatCommand(argv) {
    return argv.join(" ");
  }

  function splitLines(text) {
    var src = text == null ? "" : String(text);
    if (src === "") return [];
    var parts = src.split(/\r\n|\n|\r/);
    if (parts.length && parts[parts.length - 1] === "") parts.pop();
    return parts;
  }

  function unknownPlate(name, error, detail) {
    return {
      name: name,
      status: "unknown",
      headline: "unknown",
      detail: detail == null ? "unreadable" : detail,
      evidence: [error],
      error: error,
    };
  }

  function accessDenied(text) {
    var low = String(text || "").toLowerCase();
    for (var i = 0; i < DENY_MARKERS.length; i++) {
      if (low.indexOf(DENY_MARKERS[i]) !== -1) return true;
    }
    return false;
  }

  function parseNftRuleset(text) {
    var re = /hook\s+input\b[^}]*?policy\s+(accept|drop|reject)/gi;
    var policies = [];
    var match;
    while ((match = re.exec(String(text))) !== null) {
      policies.push(match[1].toLowerCase());
    }
    if (!policies.length) return null;
    var status;
    var policy;
    var restrictive = true;
    for (var i = 0; i < policies.length; i++) {
      if (policies[i] !== "drop" && policies[i] !== "reject") restrictive = false;
    }
    if (restrictive) {
      status = "intact";
      policy = policies[0];
    } else {
      status = "scored";
      policy = policies.indexOf("accept") !== -1 ? "accept" : policies[0];
    }
    return { backend: "nft", status: status, policy: policy, policies: policies };
  }

  function parseFirewalldState(text) {
    var low = String(text).toLowerCase();
    if (low.indexOf("not running") !== -1) return "stopped";
    if (/\brunning\b/.test(low)) return "running";
    return null;
  }

  function parseFirewalldTarget(text) {
    var match = /^\s*target:\s*(\S+)\s*$/im.exec(String(text));
    if (!match) return null;
    return match[1];
  }

  function parseUfwStatus(text) {
    var match = /Status:\s*(active|inactive)/i.exec(String(text));
    if (!match) return null;
    return match[1].toLowerCase() === "active";
  }

  function parseUfwDefault(text) {
    var match = /Default:\s*([A-Za-z]+)\s*\(incoming\)/i.exec(String(text));
    if (!match) return null;
    return match[1].toLowerCase();
  }

  function nftPlate(info) {
    return {
      name: "firewall",
      status: info.status,
      headline: "nft enabled",
      detail: info.policy + " in",
      evidence: ["nft input policy " + info.policy, "policies: " + info.policies.join(", ")],
      error: null,
    };
  }

  function stripPct(value) {
    var text = String(value).toLowerCase();
    var start = 0;
    var end = text.length;
    while (start < end && text.charAt(start) === "%") start += 1;
    while (end > start && text.charAt(end - 1) === "%") end -= 1;
    return text.slice(start, end);
  }

  function firewalldPlate(policy) {
    if (policy == null) {
      return {
        name: "firewall",
        status: "scored",
        headline: "fwd running",
        detail: "policy unknown",
        evidence: ["firewalld running", "default policy not read"],
        error: null,
      };
    }
    var norm = stripPct(policy);
    if (norm === "drop" || norm === "reject" || norm === "default") {
      var shown = norm === "drop" ? "drop" : "reject";
      return {
        name: "firewall",
        status: "intact",
        headline: "fwd running",
        detail: shown + " in",
        evidence: ["firewalld running", "target " + shown],
        error: null,
      };
    }
    if (norm === "accept") {
      return {
        name: "firewall",
        status: "scored",
        headline: "fwd running",
        detail: "accept in",
        evidence: ["firewalld running", "target accept"],
        error: null,
      };
    }
    return {
      name: "firewall",
      status: "scored",
      headline: "fwd running",
      detail: "policy unknown",
      evidence: ["firewalld running", "target " + norm],
      error: null,
    };
  }

  function ufwPlate(policy) {
    if (policy === "deny" || policy === "reject" || policy === "drop") {
      return {
        name: "firewall",
        status: "intact",
        headline: "ufw active",
        detail: policy + " in",
        evidence: ["ufw active", "default incoming " + policy],
        error: null,
      };
    }
    if (policy === "allow" || policy === "accept") {
      return {
        name: "firewall",
        status: "scored",
        headline: "ufw active",
        detail: "allow in",
        evidence: ["ufw active", "default incoming allow"],
        error: null,
      };
    }
    return {
      name: "firewall",
      status: "scored",
      headline: "ufw active",
      detail: "policy unknown",
      evidence: ["ufw active", "default policy not read"],
      error: null,
    };
  }

  function looksLikeNft(text) {
    return /\btable\s+\S+\s*\{/i.test(text) || /hook\s+input\b/i.test(text);
  }

  function firewallDenyError(text) {
    var low = String(text).toLowerCase();
    if (low.indexOf("firewall-cmd") !== -1) return "firewall-cmd: permission denied";
    if (low.indexOf("ufw") !== -1 || low.indexOf("you need to be root") !== -1) {
      return "ufw: permission denied";
    }
    if (low.indexOf("nft") !== -1 || low.indexOf("operation not permitted") !== -1 || low.indexOf("must be root") !== -1) {
      return "nft: permission denied";
    }
    return "permission denied";
  }

  function firewallFromText(text) {
    var raw = text == null ? "" : String(text);
    if (!raw.trim()) return unknownPlate("firewall", "no firewall tool found", "no tool");
    var nft = parseNftRuleset(raw);
    if (nft) return nftPlate(nft);
    var kind = parseFirewalldState(raw);
    var target = parseFirewalldTarget(raw);
    if (kind === "running" || (kind !== "stopped" && target)) return firewalldPlate(target);
    var active = parseUfwStatus(raw);
    if (active === true) return ufwPlate(parseUfwDefault(raw));
    if (accessDenied(raw)) return unknownPlate("firewall", firewallDenyError(raw), "unreadable");
    var disabled = [];
    if (looksLikeNft(raw)) disabled.push("nft has no input policy");
    if (kind === "stopped") disabled.push("firewalld not running");
    if (active === false) disabled.push("ufw inactive");
    if (disabled.length) {
      return {
        name: "firewall",
        status: "broken",
        headline: "disabled",
        detail: "no policy",
        evidence: disabled,
        error: null,
      };
    }
    return unknownPlate("firewall", "firewall state unknown", "no policy");
  }

  function splitAddr(local) {
    if (local.charAt(0) === "[") {
      var rest = local.slice(1);
      var bracket = rest.lastIndexOf("]:");
      if (bracket === -1) throw new Error("bad address: " + local);
      return [rest.slice(0, bracket), portNumber(rest.slice(bracket + 2), local)];
    }
    var text = local;
    if (text.indexOf("% ") !== -1) text = text.split("%")[0];
    var idx = text.lastIndexOf(":");
    if (idx === -1) throw new Error("bad address: " + local);
    var host = text.slice(0, idx);
    var port = portNumber(text.slice(idx + 1), local);
    if (host.indexOf("%") !== -1) host = host.split("%")[0];
    return [host, port];
  }

  function portNumber(text, original) {
    if (!/^\d+$/.test(text)) throw new Error("bad address: " + original);
    return Number(text);
  }

  function parseSs(text) {
    var found = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.toLowerCase().indexOf("netid") === 0) continue;
      var parts = line.split(/\s+/);
      if (parts.length < 5) continue;
      var protoRaw = parts[0].toLowerCase();
      var state = parts[1].toUpperCase();
      var proto;
      if (protoRaw.indexOf("tcp") === 0) {
        proto = "tcp";
        if (state !== "LISTEN") continue;
      } else if (protoRaw.indexOf("udp") === 0) {
        proto = "udp";
      } else {
        continue;
      }
      var host;
      var port;
      try {
        var split = splitAddr(parts[4]);
        host = split[0];
        port = split[1];
      } catch (err) {
        continue;
      }
      var process = "";
      if (parts.length > 5) {
        var match = /\(\("([^"]+)"/.exec(parts.slice(5).join(" "));
        if (match) process = match[1];
      }
      found.push({ proto: proto, port: port, bind: host, process: process });
    }
    return found;
  }

  function decodeProcIp(hexip) {
    if (hexip.length === 8) {
      var bytes = [];
      for (var i = 0; i < 8; i += 2) bytes.push(parseInt(hexip.slice(i, i + 2), 16));
      bytes.reverse();
      return bytes.join(".");
    }
    if (hexip.length === 32) {
      var wide = [];
      for (var index = 0; index < 32; index += 8) {
        var chunk = [];
        var slice = hexip.slice(index, index + 8);
        for (var j = 0; j < 8; j += 2) chunk.push(parseInt(slice.slice(j, j + 2), 16));
        chunk.reverse();
        for (var k = 0; k < chunk.length; k++) wide.push(chunk[k]);
      }
      return formatIpv6(wide);
    }
    throw new Error("bad proc address: " + hexip);
  }

  function formatIpv6(bytes) {
    if (bytes.length !== 16) throw new Error("bad ipv6");
    var mapped = true;
    for (var z = 0; z < 10; z++) {
      if (bytes[z] !== 0) mapped = false;
    }
    if (mapped && bytes[10] === 0xff && bytes[11] === 0xff) {
      return "::ffff:" + bytes.slice(12).join(".");
    }
    var groups = [];
    for (var i = 0; i < 16; i += 2) groups.push((bytes[i] << 8) | bytes[i + 1]);
    var bestStart = -1;
    var bestLen = 0;
    var cursor = 0;
    while (cursor < 8) {
      if (groups[cursor] === 0) {
        var end = cursor;
        while (end < 8 && groups[end] === 0) end += 1;
        if (end - cursor > bestLen) {
          bestStart = cursor;
          bestLen = end - cursor;
        }
        cursor = end;
      } else {
        cursor += 1;
      }
    }
    if (bestLen < 2) bestStart = -1;
    var parts = [];
    for (var g = 0; g < groups.length; g++) parts.push(groups[g].toString(16));
    if (bestStart < 0) return parts.join(":");
    var left = parts.slice(0, bestStart).join(":");
    var right = parts.slice(bestStart + bestLen).join(":");
    if (!left && !right) return "::";
    if (!left) return "::" + right;
    if (!right) return left + "::";
    return left + "::" + right;
  }

  function parseProcNet(text, kind) {
    var base = String(kind).indexOf("tcp") === 0 ? "tcp" : "udp";
    var found = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.toLowerCase().indexOf("sl") === 0) continue;
      var parts = line.split(/\s+/);
      if (parts.length < 4 || parts[1].indexOf(":") === -1) continue;
      var local = parts[1];
      var state = parts[3].toUpperCase();
      if (base === "tcp" && state !== "0A") continue;
      if (base === "udp" && state !== "07") continue;
      var pieces = local.split(":");
      try {
        found.push({
          proto: base,
          port: parseInt(pieces[1], 16),
          bind: decodeProcIp(pieces[0]),
          process: "",
        });
      } catch (err) {
        continue;
      }
    }
    return found;
  }

  function parseProcAuto(text) {
    var found = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.toLowerCase().indexOf("sl") === 0) continue;
      var parts = line.split(/\s+/);
      if (parts.length < 4 || parts[1].indexOf(":") === -1) continue;
      var state = parts[3].toUpperCase();
      var proto = state === "0A" ? "tcp" : state === "07" ? "udp" : "";
      if (!proto) continue;
      var pieces = parts[1].split(":");
      try {
        found.push({
          proto: proto,
          port: parseInt(pieces[1], 16),
          bind: decodeProcIp(pieces[0]),
          process: "",
        });
      } catch (err) {
        continue;
      }
    }
    return found;
  }

  function dedupeListeners(listeners) {
    var order = [];
    var byKey = {};
    for (var i = 0; i < listeners.length; i++) {
      var item = listeners[i];
      var key = item.proto + ":" + item.port;
      if (!Object.prototype.hasOwnProperty.call(byKey, key)) {
        byKey[key] = item;
        order.push(key);
      } else if (!byKey[key].process && item.process) {
        byKey[key] = item;
      }
    }
    var out = [];
    for (var j = 0; j < order.length; j++) out.push(byKey[order[j]]);
    return out;
  }

  function emptyAllowlist() {
    return { anyProto: new Set(), byProto: {}, configured: false };
  }

  function parseAllowlist(text) {
    var allowlist = emptyAllowlist();
    var raw = text == null ? "" : String(text).trim();
    if (!raw) return allowlist;
    var items = raw.split(",");
    var any = false;
    for (var i = 0; i < items.length; i++) {
      var token = items[i].trim();
      if (!token) continue;
      var portText = token;
      var proto = null;
      var slash = token.indexOf("/");
      if (slash !== -1) {
        portText = token.slice(0, slash).trim();
        proto = token.slice(slash + 1).trim().toLowerCase();
      }
      if (!/^\d+$/.test(portText)) continue;
      any = true;
      var port = Number(portText);
      if (proto) {
        if (!allowlist.byProto[proto]) allowlist.byProto[proto] = new Set();
        allowlist.byProto[proto].add(port);
      } else {
        allowlist.anyProto.add(port);
      }
    }
    allowlist.configured = any;
    return allowlist;
  }

  function allows(allowlist, proto, port) {
    if (!allowlist) return false;
    if (allowlist.anyProto && allowlist.anyProto.has(port)) return true;
    var bucket = allowlist.byProto && allowlist.byProto[proto];
    return Boolean(bucket && bucket.has(port));
  }

  function plateFromListeners(listeners, allowlist, source) {
    var allow = allowlist || emptyAllowlist();
    var unique = dedupeListeners(listeners);
    var unexpected = [];
    for (var i = 0; i < unique.length; i++) {
      if (!allows(allow, unique[i].proto, unique[i].port)) unexpected.push(unique[i]);
    }
    var status;
    var detail;
    if (unexpected.length) {
      status = "broken";
      detail = ":" + unexpected[0].port + " ?";
    } else if (unique.length) {
      status = "intact";
      detail = ":" + unique[0].port + " " + (unique[0].process || "ok");
    } else {
      status = "intact";
      detail = "none";
    }
    var evidence = [];
    if (!allow.configured && unique.length) {
      evidence.push("no allowlist configured; every listener is unexpected");
    }
    for (var j = 0; j < unique.length; j++) {
      var item = unique[j];
      var flag = allows(allow, item.proto, item.port) ? "allow" : "not in allowlist";
      evidence.push(item.proto + " :" + item.port + " " + item.bind + " " + (item.process || "-") + " " + flag);
    }
    if (!unique.length) evidence.push("no listening sockets (" + source + ")");
    evidence.push("source: " + source);
    return {
      name: "ports",
      status: status,
      headline: unique.length + " listen",
      detail: detail,
      evidence: evidence,
      error: null,
    };
  }

  function looksLikeSs(text) {
    return /^(tcp|udp)\b/im.test(text) || /^netid\b/im.test(text);
  }

  function looksLikeProc(text) {
    return /local_address/i.test(text) || /^\s*\d+:\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s/m.test(text);
  }

  function portsFromText(text, allowText) {
    var allow = parseAllowlist(allowText);
    var raw = text == null ? "" : String(text);
    if (!raw.trim()) return unknownPlate("ports", "ss not found", "no sockets");
    if (looksLikeSs(raw)) return plateFromListeners(parseSs(raw), allow, "ss");
    if (looksLikeProc(raw)) return plateFromListeners(parseProcAuto(raw), allow, "proc");
    if (accessDenied(raw)) return unknownPlate("ports", "ss: permission denied", "no sockets");
    return unknownPlate("ports", "ss failed", "no sockets");
  }

  var SSH_PATTERNS = [
    [/Accepted\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(?<addr>\S+)\s+port\s+\d+/i, "accepted"],
    [/Failed\s+\S+\s+for\s+(?:invalid user\s+)?\S+\s+from\s+(?<addr>\S+)\s+port\s+\d+/i, "failed"],
    [/Invalid user\s+\S+\s+from\s+(?<addr>\S+)/i, "failed"],
    [/authentication failure;.*rhost=(?<addr>\S+)/i, "failed"],
  ];

  function parseSshLog(text) {
    var events = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line === "-- No entries --") continue;
      var kind = null;
      var addr = null;
      for (var p = 0; p < SSH_PATTERNS.length; p++) {
        var match = SSH_PATTERNS[p][0].exec(line);
        if (match) {
          kind = SSH_PATTERNS[p][1];
          addr = match.groups.addr.replace(/:+$/, "");
          break;
        }
      }
      if (!kind || !addr) continue;
      var when = "";
      var iso = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)/.exec(line);
      var syslog = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/.exec(line);
      if (iso) when = iso[1];
      else if (syslog) when = syslog[1];
      events.push({ kind: kind, address: addr, when: when });
    }
    return events;
  }

  function dedupeEvents(events) {
    var seen = {};
    var out = [];
    for (var i = 0; i < events.length; i++) {
      var event = events[i];
      var key = event.when + "\0" + event.kind + "\0" + event.address;
      if (Object.prototype.hasOwnProperty.call(seen, key)) continue;
      seen[key] = true;
      out.push(event);
    }
    return out;
  }

  function sshPlate(events, lastN, failBroken, source) {
    var window = lastN > 0 ? events.slice(-lastN) : events.slice();
    var accepted = 0;
    var failed = 0;
    for (var i = 0; i < window.length; i++) {
      if (window[i].kind === "accepted") accepted += 1;
      if (window[i].kind === "failed") failed += 1;
    }
    var status = "intact";
    if (failed >= failBroken) status = "broken";
    else if (failed > 0) status = "scored";
    var detail = "no events";
    if (window.length) {
      var addr = window[window.length - 1].address;
      detail = addr.length <= 14 ? addr : "see log";
    }
    var evidence = ["accepted: " + accepted, "failed: " + failed, "source: " + source];
    for (var j = 0; j < window.length; j++) {
      var stamp = window[j].when ? window[j].when + " " : "";
      evidence.push((stamp + window[j].kind + " " + window[j].address).trim());
    }
    return {
      name: "ssh",
      status: status,
      headline: failed + " failed",
      detail: detail,
      evidence: evidence,
      error: null,
    };
  }

  function looksLikeSshLog(text) {
    return /sshd|Accepted\s|Failed\s|Invalid user|authentication failure|-- No entries --/i.test(text) ||
      /^\d{4}-\d{2}-\d{2}T/m.test(text) ||
      /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/m.test(text);
  }

  function sshSource(text) {
    if (/^\d{4}-\d{2}-\d{2}T/m.test(text) || text.indexOf("-- No entries --") !== -1) return "journal";
    if (/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/m.test(text)) return "/var/log/auth.log";
    return "journal";
  }

  function sshFromText(text) {
    var raw = text == null ? "" : String(text);
    if (!raw.trim()) return unknownPlate("ssh", "no ssh log source", "no log");
    var events = dedupeEvents(parseSshLog(raw));
    if (accessDenied(raw) && !events.length) {
      return unknownPlate("ssh", "permission denied", "logs unreadable");
    }
    if (events.length || looksLikeSshLog(raw)) return sshPlate(events, 20, 10, sshSource(raw));
    return unknownPlate("ssh", "no ssh log source", "no log");
  }

  function parseAptUpgradable(text) {
    var names = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.indexOf("Listing") === 0 || line.indexOf("WARNING") === 0) continue;
      if (line.indexOf("E:") === 0 || line.indexOf("W:") === 0) continue;
      var token = line.split(/\s+/)[0];
      if (token.indexOf("/") === -1 && line.indexOf("[upgradable") === -1) continue;
      names.push(token.split("/")[0]);
    }
    return names;
  }

  function parseDnfCheckUpdate(text, returncode) {
    if (returncode === 0) return [];
    if (returncode !== 100) return null;
    var names = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.toLowerCase().indexOf("last metadata") === 0) continue;
      if (line.charAt(line.length - 1) === ":" || line.indexOf("Obsoleting") === 0) continue;
      var parts = line.split(/\s+/);
      if (parts.length >= 3 && parts[0].indexOf(".") !== -1) names.push(parts[0]);
    }
    return names;
  }

  function parseCheckupdates(text, returncode) {
    if (returncode === 2) return [];
    if (returncode !== 0 && returncode != null) return null;
    if (returncode == null) return null;
    var names = [];
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.indexOf("::") === 0) continue;
      names.push(line.split(/\s+/)[0]);
    }
    return names;
  }

  function updatesPlate(backend, names) {
    var count = names.length;
    var evidence = [count + " pending via " + backend];
    var shown = names.slice(0, 8);
    for (var i = 0; i < shown.length; i++) evidence.push(shown[i]);
    if (count > 8) evidence.push(count - 8 + " more");
    return {
      name: "updates",
      status: count === 0 ? "intact" : "scored",
      headline: count + " pending",
      detail: backend,
      evidence: evidence,
      error: null,
    };
  }

  function splitExit(text) {
    var src = String(text);
    var match = /^\s*exit:\s*(-?\d+)\s*(?:\r?\n|$)/i.exec(src);
    if (!match) return { exit: null, body: src };
    return { exit: Number(match[1]), body: src.slice(match[0].length) };
  }

  function looksLikeApt(text) {
    return /\[upgradable/i.test(text) || /^Listing\b/m.test(text) || /WARNING:\s*apt/i.test(text) || /^E:/m.test(text) || /^W:/m.test(text);
  }

  function looksLikeDnf(text) {
    if (/last metadata expiration/i.test(text) || /^error:/im.test(text)) return true;
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var parts = lines[i].trim().split(/\s+/);
      if (parts.length >= 3 && parts[0].indexOf(".") !== -1 && parts[0].indexOf("/") === -1) return true;
    }
    return false;
  }

  function looksLikePacman(text) {
    return /->/.test(text) || /^::/m.test(text);
  }

  function aptPlateFrom(body, exit) {
    if (accessDenied(body)) return unknownPlate("updates", "apt: permission denied", "apt");
    if (/could not get lock|could not open lock/i.test(body)) {
      return unknownPlate("updates", "apt exited " + (exit == null ? 100 : exit), "apt");
    }
    if (exit != null && exit !== 0) return unknownPlate("updates", "apt exited " + exit, "apt");
    var names = parseAptUpgradable(body);
    if (/^E:/m.test(body) && !names.length) {
      return unknownPlate("updates", "apt exited " + (exit == null ? 100 : exit), "apt");
    }
    return updatesPlate("apt", names);
  }

  function dnfPlateFrom(body, exit) {
    if (accessDenied(body)) return unknownPlate("updates", "dnf: permission denied", "dnf");
    var rc = exit;
    if (rc == null) {
      var trial = parseDnfCheckUpdate(body, 100);
      if (trial && trial.length) rc = 100;
      else if (/last metadata expiration/i.test(body)) rc = 0;
      else rc = 1;
    }
    var names = parseDnfCheckUpdate(body, rc);
    if (names == null) return unknownPlate("updates", "dnf exited " + rc, "dnf");
    return updatesPlate("dnf", names);
  }

  function pacmanPlateFrom(body, exit) {
    if (accessDenied(body)) return unknownPlate("updates", "checkupdates: permission denied", "pacman");
    var rc = exit == null ? 0 : exit;
    var names = parseCheckupdates(body, rc);
    if (names == null) return unknownPlate("updates", "checkupdates exited " + rc, "pacman");
    return updatesPlate("pacman", names);
  }

  function updatesFromText(text) {
    var raw = text == null ? "" : String(text);
    if (!raw.trim()) return unknownPlate("updates", "no package manager check command found", "no tool");
    var split = splitExit(raw);
    var exit = split.exit;
    var body = split.body;
    if (!body.trim()) {
      if (exit === 2 || exit === 0) return updatesPlate("pacman", []);
      if (exit != null) return unknownPlate("updates", "checkupdates exited " + exit, "pacman");
      return unknownPlate("updates", "no package manager check command found", "no tool");
    }
    if (looksLikeApt(body)) return aptPlateFrom(body, exit);
    if (looksLikeDnf(body)) return dnfPlateFrom(body, exit);
    if (looksLikePacman(body)) return pacmanPlateFrom(body, exit);
    if (accessDenied(body) || /could not get lock|could not open lock/i.test(body)) {
      var backend = /dnf/i.test(body) ? "dnf" : /checkupdates|pacman/i.test(body) ? "pacman" : "apt";
      var tool = backend === "pacman" ? "checkupdates" : backend;
      if (accessDenied(body)) return unknownPlate("updates", tool + ": permission denied", backend);
      return unknownPlate("updates", tool + " exited " + (exit == null ? 100 : exit), backend);
    }
    return unknownPlate("updates", "package check unreadable", "no tool");
  }

  function baseName(path) {
    var norm = String(path).replace(/\\/g, "/");
    var parts = norm.split("/");
    return parts[parts.length - 1] || norm;
  }

  function suffixOf(path) {
    var base = baseName(path);
    var idx = base.lastIndexOf(".");
    if (idx <= 0) return "";
    return base.slice(idx).toLowerCase();
  }

  function scanText(text, rel) {
    var path = String(rel || "paste").replace(/\\/g, "/").replace(/^\.\//, "");
    var src = text == null ? "" : String(text);
    if (src.length > MAX_BYTES || SKIP_EXT[suffixOf(path)]) return [];
    if (src.slice(0, 8192).indexOf("\0") !== -1) return [];
    var lines = splitLines(src.slice(0, 8192 + MAX_BYTES));
    var hits = [];
    var seen = {};
    for (var r = 0; r < RULES.length; r++) {
      var ruleId = RULES[r][0];
      var pattern = RULES[r][1];
      if (seen[ruleId]) continue;
      for (var i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) {
          hits.push({ path: path, ruleId: ruleId, line: i + 1 });
          seen[ruleId] = true;
          break;
        }
      }
    }
    return hits;
  }

  function parseLineNo(line) {
    if (line == null || line === "") return null;
    if (typeof line === "boolean") return null;
    if (typeof line === "number") {
      if (!isFinite(line)) return null;
      return Math.trunc(line);
    }
    var text = String(line).trim();
    if (!/^[+-]?\d+$/.test(text)) return null;
    return parseInt(text, 10);
  }

  function parseSecretsweep(text) {
    var data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new Error("secretsweep JSON unreadable");
    }
    var rows;
    if (Array.isArray(data)) {
      rows = data;
    } else if (data && typeof data === "object") {
      if ("findings" in data) rows = data.findings;
      else if ("results" in data) rows = data.results;
      else if ("hits" in data) rows = data.hits;
      else rows = [];
    } else {
      throw new Error("secretsweep JSON was not a list or object");
    }
    if (!Array.isArray(rows)) throw new Error("secretsweep JSON was not a list or object");
    var hits = [];
    var pathKeys = ["path", "file", "filename"];
    var ruleKeys = ["rule_id", "rule", "id", "check_id", "check"];
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      if (!row || typeof row !== "object" || Array.isArray(row)) continue;
      var path = "";
      for (var p = 0; p < pathKeys.length; p++) {
        if (row[pathKeys[p]]) {
          path = String(row[pathKeys[p]]);
          break;
        }
      }
      var ruleId = "";
      for (var k = 0; k < ruleKeys.length; k++) {
        if (row[ruleKeys[k]]) {
          ruleId = String(row[ruleKeys[k]]);
          break;
        }
      }
      if (!path || !ruleId) continue;
      hits.push({ path: path, ruleId: ruleId, line: parseLineNo(row.line) });
    }
    return hits;
  }

  function secretsPlate(hits, root, source, truncated) {
    var count = hits.length;
    if (truncated && count === 0) return unknownPlate("secrets", "scan truncated before completion", "truncated");
    var evidence = [];
    var shown = hits.slice(0, 50);
    for (var i = 0; i < shown.length; i++) {
      if (shown[i].line) evidence.push(shown[i].path + ":" + shown[i].line + " " + shown[i].ruleId);
      else evidence.push(shown[i].path + " " + shown[i].ruleId);
    }
    if (count > 50) evidence.push(count - 50 + " more hits");
    if (count === 0) evidence.push("no hits in " + root);
    if (truncated) evidence.push("scan truncated");
    evidence.push("scanner: " + source);
    var label = baseName(root);
    return {
      name: "secrets",
      status: count === 0 ? "intact" : "broken",
      headline: count + " hits",
      detail: label.slice(0, 14) || source,
      evidence: evidence,
      error: null,
    };
  }

  function isSecretsweepDocument(text) {
    var trimmed = String(text).trim();
    if (trimmed.charAt(0) !== "{" && trimmed.charAt(0) !== "[") return false;
    var data;
    try {
      data = JSON.parse(trimmed);
    } catch (err) {
      return false;
    }
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i++) {
        var row = data[i];
        if (!row || typeof row !== "object" || Array.isArray(row)) continue;
        var hasPath = row.path || row.file || row.filename;
        var hasRule = row.rule_id || row.rule || row.id || row.check_id || row.check;
        if (hasPath && hasRule) return true;
      }
      return false;
    }
    if (data && typeof data === "object") {
      return "findings" in data || "results" in data || "hits" in data;
    }
    return false;
  }

  function secretsFromText(text, filename) {
    var raw = text == null ? "" : String(text);
    if (!raw.trim()) return unknownPlate("secrets", "scan path not found: paste", "no path");
    var path = String(filename || "").trim() || "paste";
    if (isSecretsweepDocument(raw)) {
      try {
        return secretsPlate(parseSecretsweep(raw.trim()), path, "secretsweep", false);
      } catch (err) {
        return unknownPlate("secrets", "secretsweep JSON unreadable", "secretsweep");
      }
    }
    return secretsPlate(scanText(raw, path), path, "builtin", false);
  }

  function armorMeter(statuses) {
    var list = Array.isArray(statuses) ? statuses : Array.from(statuses);
    for (var i = 0; i < list.length; i++) {
      if (VALID_STATUS.indexOf(list[i]) === -1) {
        throw new Error("invalid plate status: " + list[i]);
      }
    }
    var score = 0;
    for (var j = 0; j < list.length; j++) score += POINTS[list[j]];
    score = Math.min(100, score);
    var label = "bone";
    var broken = false;
    var allIntact = list.length > 0;
    for (var k = 0; k < list.length; k++) {
      if (list[k] === "broken") broken = true;
      if (list[k] !== "intact") allIntact = false;
    }
    if (broken) label = "blood";
    else if (allIntact) label = "steel";
    return { score: score, label: label, disclaimer: DISCLAIMER };
  }

  function meterPhrase(meter, statuses) {
    var broken = 0;
    var worn = false;
    for (var i = 0; i < statuses.length; i++) {
      if (statuses[i] === "broken") broken += 1;
      if (statuses[i] !== "intact") worn = true;
    }
    if (broken) {
      var noun = broken === 1 ? "plate" : "plates";
      return meter.label + " / " + broken + " " + noun + " broken";
    }
    if (worn) return meter.label + " / coverage worn";
    return meter.label + " / plates intact";
  }

  function plateToDict(plate) {
    return {
      name: plate.name,
      status: plate.status,
      headline: plate.headline,
      detail: plate.detail,
      evidence: plate.evidence.slice(),
      error: plate.error == null ? null : plate.error,
    };
  }

  function reportFromPlates(plates, host) {
    var statuses = [];
    for (var i = 0; i < plates.length; i++) statuses.push(plates[i].status);
    var meter = armorMeter(statuses);
    var out = [];
    for (var j = 0; j < plates.length; j++) out.push(plateToDict(plates[j]));
    return {
      host: host || "local",
      read_only: true,
      disclaimer: meter.disclaimer,
      meter: {
        score: meter.score,
        label: meter.label,
        disclaimer: meter.disclaimer,
      },
      plates: out,
    };
  }

  function evaluate(input) {
    var src = input || {};
    return reportFromPlates(
      [
        firewallFromText(src.firewall),
        portsFromText(src.ports, src.allow),
        sshFromText(src.ssh),
        updatesFromText(src.updates),
        secretsFromText(src.secrets, src.secretsPath),
      ],
      src.host
    );
  }

  function formatJson(report) {
    return JSON.stringify(report, null, 2) + "\n";
  }

  return {
    DISCLAIMER: DISCLAIMER,
    VALID_STATUS: VALID_STATUS,
    PLATE_NAMES: PLATE_NAMES,
    POINTS: POINTS,
    HEX: HEX,
    STATUS_COLOR: STATUS_COLOR,
    DENY_MARKERS: DENY_MARKERS,
    AUTH_LOG_PATHS: AUTH_LOG_PATHS,
    PROC_PATHS: PROC_PATHS,
    COMMANDS: COMMANDS,
    journalArgv: journalArgv,
    secretsweepArgv: secretsweepArgv,
    formatCommand: formatCommand,
    unknownPlate: unknownPlate,
    accessDenied: accessDenied,
    parseNftRuleset: parseNftRuleset,
    parseFirewalldState: parseFirewalldState,
    parseFirewalldTarget: parseFirewalldTarget,
    parseUfwStatus: parseUfwStatus,
    parseUfwDefault: parseUfwDefault,
    firewallFromText: firewallFromText,
    splitAddr: splitAddr,
    parseSs: parseSs,
    decodeProcIp: decodeProcIp,
    parseProcNet: parseProcNet,
    parseAllowlist: parseAllowlist,
    allows: allows,
    plateFromListeners: plateFromListeners,
    portsFromText: portsFromText,
    parseSshLog: parseSshLog,
    dedupeEvents: dedupeEvents,
    sshPlate: sshPlate,
    sshFromText: sshFromText,
    parseAptUpgradable: parseAptUpgradable,
    parseDnfCheckUpdate: parseDnfCheckUpdate,
    parseCheckupdates: parseCheckupdates,
    updatesPlate: updatesPlate,
    updatesFromText: updatesFromText,
    scanText: scanText,
    parseSecretsweep: parseSecretsweep,
    secretsPlate: secretsPlate,
    secretsFromText: secretsFromText,
    armorMeter: armorMeter,
    meterPhrase: meterPhrase,
    evaluate: evaluate,
    formatJson: formatJson,
  };
});
