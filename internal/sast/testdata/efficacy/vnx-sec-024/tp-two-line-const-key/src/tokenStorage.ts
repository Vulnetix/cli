const TOKEN_KEY = "auth_token";
const THEME_KEY = "ui_theme";

export class TokenStorage {
  save(token: string, theme: string): void {
~>    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(THEME_KEY, theme);
  }
}
