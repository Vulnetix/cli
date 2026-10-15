export async function login(username, password) {
~>  console.log(
    "login attempt",
    username,
    btoa(password)
  );
  return fetch("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
}
