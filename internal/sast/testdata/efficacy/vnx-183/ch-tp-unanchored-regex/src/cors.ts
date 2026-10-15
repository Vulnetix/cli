export function allowOrigin(origin: string): boolean {
~>  return /^https:\/\/app\.acme\.com/.test(origin);
}

export function trustedOrigin(origin: string): boolean {
~>  return /acme\.com$/.test(origin);
}

export function partnerOrigin(origin: string): boolean {
~>  return /^https:\/\/partner.acme.com$/.test(origin);
}
