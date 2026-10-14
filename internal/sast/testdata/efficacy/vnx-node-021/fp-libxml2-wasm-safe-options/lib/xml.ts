import { XmlDocument, ParseOption } from 'libxml2-wasm'

// XML_PARSE_NOENT would substitute entities; only NONET and NOBLANKS are set.
export function parse(data: string): string {
  const option = ParseOption.XML_PARSE_NONET | ParseOption.XML_PARSE_NOBLANKS
  const doc = XmlDocument.fromString(data, { option })
  try {
    return doc.toString()
  } finally {
    doc.dispose()
  }
}
