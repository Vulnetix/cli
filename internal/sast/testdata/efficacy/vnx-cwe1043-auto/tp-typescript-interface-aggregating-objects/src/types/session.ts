import type { User, Org, Plan } from './models'

~>export interface SessionState {
  user: User
  org: Org
  plan: Plan
  roles: Role[]
  preferences: Record<string, Preference>
  cart?: Cart
  billing: Address
  shipping: Address
  flags: FeatureFlags
  notifications: Notification[]
  socket: WebSocket | null
  token: string
  expiresAt: number
  admin: boolean
}

export function emptySession(): Partial<SessionState> {
  return {}
}
