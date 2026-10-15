import { Server } from 'socket.io';

export function attach(httpServer: any) {
  return new Server(httpServer, {
    cors: { origin: ['https://app.example.com'], credentials: true },
  });
}
