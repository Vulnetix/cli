export function remember(exp: number) {
  localStorage.setItem("theme", "dark");
  localStorage.setItem("tokenExpiresAt", String(exp));
  localStorage.setItem("lastTokenRefresh", Date.now().toString());
  localStorage.setItem("tokenizerModel", "cl100k");
  localStorage.setItem("sidebarCollapsed", "true");
}
