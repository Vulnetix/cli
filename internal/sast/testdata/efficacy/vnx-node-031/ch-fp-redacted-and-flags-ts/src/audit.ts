export function audit(user: { id: string }, password: string, token: string) {
  logger.info('login', { userId: user.id, password: '[REDACTED]' });
  console.log({ hasPassword: Boolean(password) });
  logger.debug('token length', token.length);
}
