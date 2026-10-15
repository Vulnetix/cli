import Cookies from "js-cookie";

export function store(token) {
  Cookies.set("access_token", token, { secure: true, sameSite: "strict" });
  const old = localStorage.getItem("token");
  if (old) {
    localStorage.removeItem("token");
    localStorage.removeItem("refresh_token");
  }
  return localStorage.token === undefined;
}
