// Validates the session token and rejects expired ones.
function check(token) {
  return verify(token);
}
