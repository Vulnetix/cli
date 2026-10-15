export class LoginComponent {
  submit() {}
  totp(name: string, email: string, secret: string) {
    return `otpauth://totp/${name}:${email}?secret=${secret}&issuer=${name}`;
  }
}
