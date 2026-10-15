const LINK = 'https://wiki.example.com/#TODO-security-add-auth';
const msg = `TODO: add CSRF token`;

export function help() {
  // TODO: no-op on SSR
  return [LINK, msg];
}
