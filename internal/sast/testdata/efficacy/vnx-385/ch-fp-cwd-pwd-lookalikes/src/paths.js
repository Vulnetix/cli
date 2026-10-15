const path = require("path");

function insideRoot(root) {
  const pwd = process.cwd();
  if (pwd === root) {
    return true;
  }
  return path.relative(root, pwd) === "";
}

function onChange(event, state) {
  if (event.target.name === "password") {
    state.touched = true;
  }
  if (typeof state.password !== "string") {
    return false;
  }
  if (state.passwordInput.value === state.passwordConfirm.value) {
    return true;
  }
  return state.passwordStrength === Strength.WEAK;
}
