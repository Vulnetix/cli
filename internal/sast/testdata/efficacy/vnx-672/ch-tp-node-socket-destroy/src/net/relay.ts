import net from 'net';

export function relay(sock: net.Socket, data: Buffer) {
  sock.destroy();
~>  sock.write(data);
}

export function closeDb(db: any) {
  db.close();
~>  db.run('DELETE FROM sessions');
}
