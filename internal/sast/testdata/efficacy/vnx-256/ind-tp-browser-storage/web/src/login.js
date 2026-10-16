import { api } from "./api";

export async function onLogin(form) {
  const username = form.username.value;
  const password = form.password.value;
  const res = await api.post("/login", { username, password });
  if (form.remember.checked) {
~>    localStorage.setItem("password", password);
~>    document.cookie = "pwd=" + encodeURIComponent(password) + "; path=/";
  }
  return res;
}
