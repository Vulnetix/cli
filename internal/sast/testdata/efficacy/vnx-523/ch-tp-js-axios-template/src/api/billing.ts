import axios from "axios";

export async function invoices(token: string) {
~>  return axios.get(`http://billing.acme-corp.net/v1/invoices`, { headers: { Authorization: `Bearer ${token}` } });
}

export async function signIn(email: string, password: string) {
~>  return fetch("http://auth.acme-corp.net/session", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}
