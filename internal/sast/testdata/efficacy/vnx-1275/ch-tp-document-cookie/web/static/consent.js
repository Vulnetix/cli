export function rememberConsent(id) {
~>  document.cookie = `consent_id=${id}; Path=/; SameSite=None; Secure`;
}
