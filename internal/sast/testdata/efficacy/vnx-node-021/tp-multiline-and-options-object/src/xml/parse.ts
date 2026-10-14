import libxml from 'libxmljs2'

export function parseInvoice(xml: string) {
  return libxml.parseXmlString(xml, {
    dtdload: true,
~>    noent: true,
  })
}

const OPTIONS = {
~>  noent : true,
  nonet: false,
}

export function parseFeed(xml: string) {
  return libxml.parseXml(xml, OPTIONS)
}
