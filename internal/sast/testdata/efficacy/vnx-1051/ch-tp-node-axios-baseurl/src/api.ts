import axios from "axios";

export const billing = axios.create({
~>  baseURL: "http://10.8.0.21:4000/v2",
  timeout: 5000,
});
