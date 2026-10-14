import { deserialize } from 'bson'
import avro from 'avsc'
import { unserialize as phpUnserialize } from 'php-serialize'

export class MessageCodec {
  deserialize(input: Buffer) {
    return deserialize(input)
  }

  unserialize(text: string) {
    return JSON.parse(text)
  }
}

export function decodeEvent(type: avro.Type, buf: Buffer) {
  return type.fromBuffer(buf)
}

export function legacy(req: { body: string }) {
  return phpUnserialize(req.body)
}

export const codec = new MessageCodec()
export const value = codec.deserialize(Buffer.alloc(0))
