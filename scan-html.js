// shield/scan-html.js — static HTML threat scan. Text analysis only: never
// renders, never executes. Lower score is cleaner.
function scanHtml(html) {
  const signals = [];
  const add = (name, weight, detail) => signals.push({ name, weight, detail });
  const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  const js = scripts.join("\n");
  const text = html.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  const urls = [...new Set([...html.matchAll(/https?:\/\/[^\s"'`<>()]+/gi)].map((m) => m[0].replace(/[.,;]+$/, "")))];
  const ips = [...new Set(urls.map((u) => (u.match(/https?:\/\/(\d{1,3}(?:\.\d{1,3}){3})/) || [])[1]).filter(Boolean))];

  if (/<meta[^>]*http-equiv\s*=\s*["']?refresh/gi.test(html)) add("meta-refresh", 3, "auto-navigation without click");
  if (/window\.location|location\.(href|replace|assign)/i.test(js)) add("js-redirect", 3, "script takes you somewhere");
  if (/redirect/i.test(js) && /setTimeout|setInterval/i.test(js)) add("timed-redirect", 2, "redirect on a timer");
  if (/redirecting in\b/i.test(html)) add("countdown-lure", 2, "countdown pressure text");
  if (ips.length) add("bare-ip-target", 3, ips.join(", "));
  if (urls.some((u) => u.startsWith("http://"))) add("plain-http", 1, "unencrypted link in file");
  if (/[?&]id=[0-9a-f]{16,}/i.test(html)) add("tracking-id", 1, "per-victim tracking token");
  const directBeacon = (html.match(/<img[^>]*src\s*=\s*"http/gi) || []).length + (/image\.\w+\s*\.src\s*=\s*["']http/i.test(js) ? 1 : 0);
  const stealthBeacon = /\.src\s*=/.test(js) && urls.some((u) => /\.(png|jpe?g|gif|webp|svg)(\?|$)/i.test(u));
  if (directBeacon || stealthBeacon) add("remote-image-beacon", 2, "opening the file phones home");
  if (/(seed phrase|mnemonic|private key|type\s*=\s*["']?password)/i.test(html)) add("credential-harvest", 4, "asks for secrets");
  if (/atob\s*\(|fromCharCode|(?:\\x[0-9a-fA-F]{2}){4,}/.test(js)) add("obfuscation", 2, "hidden code");
  const blobs = [...html.matchAll(/base64,[A-Za-z0-9+/=]{50000,}/g)];
  if (blobs.length) add("giant-embedded-blob", 1, "bulk used as camouflage");

  if (/ld\+json/i.test(html) && text.length < 200 && /window\.location|location\.(href|replace|assign)/i.test(js)) add("seo-shell", 2, "fake content around a redirect");
  if (urls.some((u) => /(confirm|transaction|verify|secure|wallet|bank|login|prize|claim|giveaway)/i.test(u))) add("lure-url-words", 2, "scam-flavored URL words");
  if (/small photography studio publishing limited-edition/i.test(html)) add("known-kit", 2, "matches active scam-kit template (Oct 11 wave)");
  const score = signals.reduce((a, s) => a + s.weight, 0);
  const verdict = score === 0 ? "CLEAN" : score <= 3 ? "LOOK" : score <= 7 ? "SUSPICIOUS" : "MALICIOUS";
  return { verdict, score, signals, iocs: { urls, ips }, visibleText: text.slice(0, 300) };
}
module.exports = { scanHtml };
