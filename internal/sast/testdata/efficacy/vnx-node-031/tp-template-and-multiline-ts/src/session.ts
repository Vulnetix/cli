import winston from 'winston';

export function onLogin(userId: string, sessionToken: string, secret: string): void {
~>  winston.info(`login ok for ${userId} with session ${sessionToken}`);
~>  this.logger.warn(
    'signing with',
    secret,
  );
}
