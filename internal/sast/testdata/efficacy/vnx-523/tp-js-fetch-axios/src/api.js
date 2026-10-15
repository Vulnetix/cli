import axios from "axios";

export async function signIn(email, password) {
~>  const res = await fetch("http://api.shop-example.io/session", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  return res.json();
}

export function report(apiToken) {
~>  return axios.get(`http://reports.shop-example.io/daily`, {
    headers: { Authorization: `Bearer ${apiToken}` },
  });
}

export function legacy(user, pass) {
~>  return axios.post("http://legacy.shop-example.io/rpc", {}, { auth: { username: user, password: pass } });
}
