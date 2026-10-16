import { XmlDocument, ParseOption } from 'libxml2-wasm';

export function parse(s: string) {
~>  return XmlDocument.fromString(s, { option: ParseOption.XML_PARSE_NOENT });
}
