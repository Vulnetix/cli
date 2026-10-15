export function isAdmin(input: string, cfg: { adminPassword: string }): boolean {
~>  return input == cfg.adminPassword;
}
