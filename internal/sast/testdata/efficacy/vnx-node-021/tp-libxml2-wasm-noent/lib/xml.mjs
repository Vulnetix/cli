import { XmlDocument, ParseOption } from 'libxml2-wasm'

export function parseUpload(data) {
~>  const option = ParseOption.XML_PARSE_NOENT | ParseOption.XML_PARSE_DTDLOAD
  const doc = XmlDocument.fromString(data, { option })
  const text = doc.toString()
  doc.dispose()
  return text
}
