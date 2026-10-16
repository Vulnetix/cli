const ok = /^https:\/\/([a-z]+\.)?example\.com(:\d+)?$/.test(origin)
const path = /^\/api\/v\d+\//.test(req.url)
const word = /^[a-z0-9._-]+$/i.test(slug)
// /^https:\/\/example.com/.test(o)
const doc = "pattern /^https:\/\/example.com/ is bad"
