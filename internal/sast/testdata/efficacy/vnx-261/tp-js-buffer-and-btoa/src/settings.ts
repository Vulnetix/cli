export function storeDbPassword(store: Map<string, string>, dbPassword: string): void {
~>  store.set('db', Buffer.from(dbPassword, 'utf8').toString('hex'));
}
