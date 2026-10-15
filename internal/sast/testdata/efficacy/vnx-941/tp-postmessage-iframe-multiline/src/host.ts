export function sendSession(frame: HTMLIFrameElement, session: { id: string; user: string }): void {
~>  frame.contentWindow!.postMessage(
    { kind: 'session', id: session.id, user: session.user },
    '*'
  );
}

export function notify(popup: Window, data: unknown) {
~>  popup.postMessage(data, `*`);
}
