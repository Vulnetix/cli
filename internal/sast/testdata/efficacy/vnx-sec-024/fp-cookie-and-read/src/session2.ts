export function useSession(token: string): void {
  sessionStorage.setItem("access_token", token);
  const t = localStorage.getItem("access_token") ?? "";
  console.log("localStorage.setItem('token', x) is not used here", t.length);
  localStorage.setItem("lastRoute", window.location.pathname);
}
