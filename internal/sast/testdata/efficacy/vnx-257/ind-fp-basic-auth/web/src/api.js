export function authHeader(username, password) {
  return { Authorization: "Basic " + btoa(username + ":" + password) };
}
