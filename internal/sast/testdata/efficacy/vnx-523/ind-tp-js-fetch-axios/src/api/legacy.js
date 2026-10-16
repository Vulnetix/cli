import axios from "axios";

export async function getProfile(token) {
~>  const res = await fetch("http://api.legacy-crm.com/v2/profile", {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

export function signIn(email, password) {
~>  return axios.post("http://auth.legacy-crm.com/session", { email, password });
}
