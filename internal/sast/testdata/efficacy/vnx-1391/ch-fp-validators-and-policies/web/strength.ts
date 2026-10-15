const banned: string[] = ['123456', 'qwerty', 'abc123'];

export function score(password: string): number {
  if (password === 'qwerty' || banned.includes(password)) return 0;
  return zxcvbn(password).score;
}
