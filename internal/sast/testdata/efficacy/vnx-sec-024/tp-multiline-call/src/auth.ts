import axios from "axios";

export async function login(user: string, pass: string): Promise<void> {
  const res = await axios.post("/api/login", { user, pass });
~>  window.localStorage.setItem(
    "refresh_token",
    res.data.refresh_token,
  );
~>  localStorage.setItem( 'accessToken' , res.data.accessToken );
}
