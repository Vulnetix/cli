// Server reads req.body.passwordRepeat and compares it with the password.
const fields = ['email', 'password', 'passwordRepeat'];
export function payload(form) {
  return { email: form.email, password: form.password, passwordRepeat: form.passwordRepeat };
}
