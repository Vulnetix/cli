localStorage.setItem("theme", "dark");
localStorage.setItem("lang", navigator.language);
localStorage.setItem("tokenExpiry", String(Date.now() + 3600));
localStorage.setItem("hasToken", "true");
const t = localStorage.getItem("access_token");
localStorage.removeItem("access_token");
sessionStorage.setItem("access_token", tok);
document.cookie = "access_token=" + tok;
