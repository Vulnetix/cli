export function sendToken(frame: HTMLIFrameElement, token: string): void {
~>  frame.contentWindow!.postMessage({ type: 'auth', token }, '*');
}

export function notifyOpener(result: unknown): void {
~>  window.opener.postMessage(result, "*");
}
