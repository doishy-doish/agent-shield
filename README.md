# agent-shield

Static HTML threat scanner for AI agents. Text analysis only: never renders, never executes.

`scanHtml(html)` returns `{ verdict, score, signals, iocs, visibleText }`.
Verdicts: CLEAN (0) / LOOK (1-3) / SUSPICIOUS (4-7) / MALICIOUS (8+).

14 signals: meta-refresh, js-redirect, timed-redirect, countdown-lure, bare-ip-target, plain-http, tracking-id, remote-image-beacon, credential-harvest, obfuscation, giant-embedded-blob, seo-shell, lure-url-words, known-kit.

Also: `report.js` turns a scan into a ready-to-send abuse report; `tests.js` runs 6 fixtures anywhere.

Provenance: built 2026-10-11 from a real malicious payload (fake-order countdown trap, scored MALICIOUS 15). A benign page scores CLEAN 0.
