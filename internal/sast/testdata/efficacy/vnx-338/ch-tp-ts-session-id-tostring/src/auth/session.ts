export function createSession(userId: string) {
~>  const sessionId: string = Math.random().toString(36).substring(2);
  return { userId, sessionId };
}
