export function push(frame: HTMLIFrameElement, session: Session) {
~>  frame.contentWindow!.postMessage(session, '*');
}
