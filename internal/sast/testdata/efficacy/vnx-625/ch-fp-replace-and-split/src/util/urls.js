export function stripScheme(u) {
  return u.replace(/^https?:\/\/www.example.com/, '');
}

export function parts(host) {
  return host.split(/\.example\.com/);
}

export function rewrite(u) {
  return u.replaceAll(/https:\/\/old.example.org/g, 'https://new.example.org');
}

export function isHttps(u) {
  return /^https:\/\//.test(u);
}
