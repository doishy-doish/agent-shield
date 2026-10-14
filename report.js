// shield/report.js — turns a scanHtml() result into a ready-to-send abuse
// report (Fiverr Trust & Safety, registrar, host). Pure strings, no I/O.
function formatReport(scan, meta) {
  const m = meta || {};
  const lines = [];
  lines.push("Malicious file/link report");
  if (m.who) lines.push("Sender: " + m.who);
  if (m.where) lines.push("Received via: " + m.where);
  if (m.filename) lines.push("Filename: " + m.filename);
  lines.push("Verdict: " + scan.verdict + " (score " + scan.score + ")");
  lines.push("");
  lines.push("What it does:");
  scan.signals.forEach((s) => lines.push("- " + s.name + ": " + s.detail));
  lines.push("");
  lines.push("IOCs (blocklist these):");
  scan.iocs.ips.forEach((ip) => lines.push("- IP: " + ip));
  scan.iocs.urls.forEach((u) => lines.push("- URL: " + u));
  if (scan.visibleText) lines.push("\nVisible page text: \"" + scan.visibleText + "\"");
  return lines.join("\n");
}
module.exports = { formatReport };
