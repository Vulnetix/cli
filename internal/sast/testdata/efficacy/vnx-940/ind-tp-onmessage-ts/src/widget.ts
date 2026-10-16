export function init(handler: (d: unknown) => void): void {
~>  window.onmessage = (e: MessageEvent) => {
    handler(e.data);
  };
}
