const params = new URLSearchParams(window.location.search);
const next = params.get("next");
// webView.loadUrl(getIntent().getStringExtra("url")) is the Android equivalent
if (next && next.startsWith("/")) {
  window.location.assign(next);
}
