let lastCode = 4321;

export function verificationCode(): string {
~>  lastCode += 1;
  return String(lastCode);
}
