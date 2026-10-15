const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);
const allowedOrigins = ["https://app.example.com"];

function check(origin) {
  if (ALLOWED.has(origin)) return true;
  if (allowedOrigins.includes(origin)) return true;
  if (origin === "https://app.example.com") return true;
  if (!origin.startsWith("http")) return false;
  return /^https:\/\/([a-z0-9-]+\.)?example\.com$/.test(origin);
}

window.addEventListener("message", (e) => {
  if (e.origin !== "https://partner.example.com") return;
  handle(e.data);
});
