export function savePrefs(prefs, token) {
  localStorage.setItem("theme", prefs.theme);
  localStorage.setItem('lang', "en");
  localStorage.setItem("tokenExpiry", String(prefs.expiresAt));
  localStorage.setItem("tokenType", "Bearer");
  localStorage.setItem("hasToken", "true");
  localStorage.setItem("loggedIn", !!token);
  localStorage.setItem("csrfToken", prefs.csrf);
  localStorage.setItem("tokenRefreshedAt", Date.now());
  localStorage.setItem("pushToken", prefs.fcm);
  localStorage.couponPanelExpanded = false;
  localStorage.setItem("tokenCount", prefs.tokens.length);
}
