export function warnCrossSite(cookie) {
  if (cookie.sameSite == 'none' && !cookie.secure) {
    console.warn('cross-site cookie without Secure');
  }
  cookie.sameSite = 'lax';
  document.cookie = `theme=dark; Path=/; SameSite=Lax`;
}
