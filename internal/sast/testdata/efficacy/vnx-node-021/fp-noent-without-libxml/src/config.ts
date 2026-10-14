import { XMLParser } from 'fast-xml-parser'

// fast-xml-parser never resolves external entities.
const parser = new XMLParser({ processEntities: true })

export const flags = {
  noent: true,
  verbose: false,
}

export function read(xml: string) {
  return parser.parse(xml)
}
