import axios from "axios";

export async function login(email: string, password: string) {
  const response = await axios.post("/api/login", { email, password });
~>  localStorage.setItem("accessToken", response.data.accessToken);
~>  window.localStorage.setItem('user', JSON.stringify({ email, token: response.data.token }));
  return response.data;
}
