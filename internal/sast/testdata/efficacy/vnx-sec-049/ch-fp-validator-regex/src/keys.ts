const ADMIN_KEY_RE = /^sk-ant-admin01-[A-Za-z0-9_-]{93}AA$/;

export function isAdminKey(value: string): boolean {
  return ADMIN_KEY_RE.test(value);
}
