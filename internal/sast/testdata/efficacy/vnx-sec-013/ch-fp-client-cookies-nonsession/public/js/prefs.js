export function savePrefs(theme, lang) {
  document.cookie = `theme=${theme}; path=/; max-age=31536000`;
  document.cookie = "lang=" + lang + "; path=/";
}

export function hasSession() {
  return document.cookie.split('; ').some((c) => c.startsWith('sessionid='));
}

export function logout() {
  document.cookie = 'auth_token=; Max-Age=0; path=/';
}
