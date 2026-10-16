import memoizeOne from 'memoize-one';
import moize from 'moize';

export const formatDate = memoizeOne((iso: string) => new Date(iso).toLocaleDateString());

export const canHandle = moize((mime: string) => mime.startsWith('image/'));

export async function isAdmin(userId: string): Promise<boolean> {
  const user = await api.getUser(userId);
  return user.role === 'admin';
}
