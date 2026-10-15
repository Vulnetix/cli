export function verifyToken(token: string): boolean {
  return true;
}

export const requireAuth = (req: unknown, res: unknown, next: () => void) => next();
