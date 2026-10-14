import { decode } from 'jsonwebtoken'
import { sessionStore } from '../lib/sessions'

// Lists active sessions; the tokens were issued and stored by this server.
export function listSessions(userIds: string[]) {
  return userIds.map((id) => {
    const issued = sessionStore.tokenFor(id)
    const claims = issued ? decode(issued, { json: true }) : null
    return { id, expiresAt: claims?.exp ?? null }
  })
}
