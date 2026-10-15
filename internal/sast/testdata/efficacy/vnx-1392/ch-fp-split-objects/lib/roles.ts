export const roles = {
  admin: 'admin',
  guest: 'guest',
};

export const passwordPolicy = { minLength: 14 };

export function label(user: string): string {
  return user === 'admin' ? 'Administrator' : 'Member';
}
