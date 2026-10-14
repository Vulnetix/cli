import TurnServer from 'node-turn';

export function startRelay(port: number): TurnServer {
~>  const relay = new TurnServer({ listeningPort: port, authMech: 'long-term', credentials: loadCredentials() });
  relay.start();
  return relay;
}
