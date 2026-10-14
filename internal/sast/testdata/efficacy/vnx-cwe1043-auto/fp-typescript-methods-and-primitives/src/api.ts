export interface Settings {
  theme: 'light' | 'dark'
  locale: string
  fontSize: number
  compact: boolean
  timezone?: string
  createdAt: string
  updatedAt: string
  tags: string[]
  owner: string | null
  id: number
  version: bigint
  notes: unknown
}

export class Api {
  getUser(id: string): Promise<User> { return fetch(id) }
  getOrg(id: string): Promise<Org> { return fetch(id) }
  getPlan(id: string): Promise<Plan> { return fetch(id) }
  private client: HttpClient
  private cache: Cache
  constructor(client: HttpClient) {
    this.client = client
  }
  listRoles(): Role[] { return [] }
  listCarts(): Cart[] { return [] }
  listOrders(): Order[] { return [] }
  listLines(): Line[] { return [] }
  listTaxes(): Tax[] { return [] }
  listFlags(): Flag[] { return [] }
  listAudit(): Audit[] { return [] }
}
