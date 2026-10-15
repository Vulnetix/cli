const crypto = require("crypto");

let currentHash = "";

window.addEventListener("hashchange", () => {
  const hash = window.location.hash;
  if (hash && hash !== currentHash) {
    currentHash = hash;
    render(hash.slice(1));
  }
});

function cacheKey(body) {
  const digest = crypto.createHash("sha1").update(body).digest("hex");
  return "etag-" + digest.slice(0, 12);
}
module.exports = { cacheKey };
