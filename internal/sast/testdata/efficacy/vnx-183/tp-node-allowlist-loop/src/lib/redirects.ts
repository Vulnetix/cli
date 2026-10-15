const redirectAllowlist = new Set([
  'https://github.com/acme/shop',
  'https://blog.acme.io'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
~>    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}

export function checkTarget (toUrl: string, trustedPrefixes: string[]) {
  return trustedPrefixes.some((trusted) =>
~>    toUrl.startsWith(trusted))
}

export function corsOrigin (origin: string) {
~>  return origin.indexOf('acme.io') !== -1
}
