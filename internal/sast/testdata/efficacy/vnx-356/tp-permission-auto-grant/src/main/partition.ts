import { session } from 'electron';

export function setupPartition(name: string): void {
  const ses = session.fromPartition(name);
~>  ses.setPermissionRequestHandler(
    (_contents, _permission, cb) => cb(true),
  );
}
