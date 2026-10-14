import { deserialize } from 'serialize-to-js'
import fs from 'node:fs/promises'

export async function restoreCart(req) {
  const body = await req.text()
~>  const cart = deserialize(body)
  return cart.items
}

const stj = require('serialize-to-js')
export function fromQuery(url) {
  const payload = new URL(url).searchParams.get('s')
~>  return stj.deserialize(payload)
}
