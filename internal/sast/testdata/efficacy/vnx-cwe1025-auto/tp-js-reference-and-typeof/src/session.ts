import type { Session } from './types';

export function hasScopes(session: Session): boolean {
~>  return session.scopes !== [];
}

export function isGuest(session: Session): boolean {
~>  return session.user.constructor.name == "GuestUser";
}
