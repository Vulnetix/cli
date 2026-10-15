function login(username, password) {
~>  console.log("login attempt", username, btoa(password));
  return api.post("/login", { username, password });
}
