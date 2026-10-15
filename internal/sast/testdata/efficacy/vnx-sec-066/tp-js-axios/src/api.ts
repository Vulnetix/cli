import axios from "axios";

export const api = axios.create({
  baseURL: "https://api.acme-corp.io",
~>  headers: { Authorization: `Bearer @@sample:[A-Za-z0-9_-]{48}@@` },
});
