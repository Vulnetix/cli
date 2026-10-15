import axios from "axios";

// TODO remove before release
~>// apiKey = "k8s9Dd02lQx7"
export const client = axios.create({
  baseURL: process.env.API_URL,
~>  headers: { "X-Api-Key": process.env.API_KEY }, // api_key: Zx81!temp
});
