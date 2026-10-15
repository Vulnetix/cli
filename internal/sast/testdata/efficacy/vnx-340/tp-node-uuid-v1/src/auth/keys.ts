import { v1 } from 'uuid'

export function newApiKey (): string {
~>  return v1()
}
