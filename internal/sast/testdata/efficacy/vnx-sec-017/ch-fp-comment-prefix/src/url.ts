// Legacy brokers used amqp://rabbit.internal.acmecorp.net:5672 before the TLS cutover.
export function isPlainRedis(url: string): boolean {
  return url.startsWith("redis://");
}

/*
 * ldap://ldap.corp.acmecorp.io is no longer reachable.
 */
export const SCHEMES = ["redis://", "amqp://", "ftp://"];
