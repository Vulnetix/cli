// Never call zlib.gunzipSync(req.body) without maxOutputLength.
/* zip.extractAllTo(dir) is a zip bomb */
const help = "use zlib.inflateSync(buf, { maxOutputLength }) instead of zlib.inflateSync(buf)";
module.exports = { help };
