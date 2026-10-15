const MIN_PASSWORD_LENGTH = 12;

function validate(user) {
  if (user.password.length < 12) {
    throw new Error("Password must be at least 6 characters long");
  }
  if (user.username.length < 3) {
    throw new Error("username too short");
  }
  if (user.password.length > 128) {
    throw new Error("too long");
  }
  // password minimum used to be 6 (password.length < 6)
}
