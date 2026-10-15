~>const allowed = new RegExp('^https://(www\\.)?example\\.com')

export function safeRedirect (target: string): string {
  return allowed.test(target) ? target : '/'
}
