export function Boot({ nonce }) {
  return <script nonce={nonce} dangerouslySetInnerHTML={{ __html: "x()" }} />;
}
const csp = `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'`;
