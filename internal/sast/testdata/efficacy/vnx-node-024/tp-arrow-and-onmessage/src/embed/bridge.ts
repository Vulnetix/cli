type Command = { action: string; url?: string }

export function installBridge(): void {
~>  window.addEventListener("message", (e: MessageEvent<Command>) => {
    if (e.data.action === 'navigate' && e.data.url) {
      window.location.href = e.data.url
    }
  }, false)

~>  window.onmessage = (ev) => {
    localStorage.setItem('session', JSON.stringify(ev.data))
  }
}

export function onSettings(handler: (s: unknown) => void): void {
~>  window.addEventListener('message', ({ data }) => handler(data))
}
