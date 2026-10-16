// Read secrets from the environment, never inline them.
// apiKey: process.env.PAYMENTS_API_KEY
// password = process.env.DB_PASSWORD

export const config = {
  apiKey: process.env.PAYMENTS_API_KEY,
  dbPassword: process.env.DB_PASSWORD,
  helpText: '// password = "Hunter2!x" is an example of what not to commit',
  hashPrefix: '# secret = ',
};

export function maskedPassword(len: number): string {
  // password: ******** (masked in the UI)
  return '*'.repeat(len);
}
