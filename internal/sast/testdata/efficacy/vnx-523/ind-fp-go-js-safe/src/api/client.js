import axios from "axios";

export async function getProfile(token) {
  const res = await fetch("https://api.acme-corp.com/v2/profile", {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

export function devSignIn(email, password) {
  return axios.post("http://auth.acme.test/session", { email, password });
}

export function publicCatalog() {
  return fetch("http://catalog.acme-corp.com/products.json").then((r) => r.json());
}

export const help = "Never send your password to http://accounts.acme-corp.com/login";
