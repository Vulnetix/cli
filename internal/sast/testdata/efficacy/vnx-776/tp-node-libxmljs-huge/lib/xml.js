const libxmljs = require('libxmljs')

function parseUpload (buf) {
~>  return libxmljs.parseXml(buf.toString(), { huge: true })
}

function parseFeed (text) {
  const doc = libxmljs.parseXmlString(text, {
    noblanks: true,
~>    huge: true
  })
  return doc
}

async function parseWasm (libxml2, data) {
~>  const option = @@sample:l[i]bx[m]l2[.]Pa[r]se[O]pt[i]on[.]XM[L][_]P[A]RS[E][_]H[U]GE@@ | @@sample:l[i]bx[m]l2[.]Pa[r]se[O]pt[i]on[.]XM[L][_]P[A]RS[E][_]N[O]BL[A]NK[S]@@
  return @@sample:l[i]bx[m]l2[.]Xm[l]Do[c]um[e]nt[.]fr[o]mS[t]ri[n]g@@(data, { option })
}

module.exports = { parseUpload, parseFeed, parseWasm }
