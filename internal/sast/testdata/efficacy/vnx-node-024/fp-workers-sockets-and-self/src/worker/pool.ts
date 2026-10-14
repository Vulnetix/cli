const worker = new Worker(new URL('./hash.worker.ts', import.meta.url))
worker.addEventListener('message', (e) => {
  console.log('hash', e.data)
})
worker.postMessage({ file: 'a.bin' })

const ws = new WebSocket('wss://feed.example.com')
ws.addEventListener('message', (e) => console.log(e.data))

const channel = new MessageChannel()
channel.port1.addEventListener('message', (e) => console.log(e.data))

process.on('message', (msg) => console.log(msg))

// Posting to this same window: targetOrigin '*' cannot reach another origin.
window.postMessage('zero-timeout', '*')
self.postMessage({ done: true })

// window.addEventListener('message', (e) => eval(e.data))
const doc = "window.addEventListener('message', handler) without an origin check"
export default doc
