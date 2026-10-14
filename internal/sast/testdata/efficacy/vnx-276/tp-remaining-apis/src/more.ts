import * as fs from 'fs';

export function more(fd: number): void {
~>  fs.fchmodSync(fd, 0o666);
~>  fs.fchmod(fd, 0o777, () => undefined);
}
