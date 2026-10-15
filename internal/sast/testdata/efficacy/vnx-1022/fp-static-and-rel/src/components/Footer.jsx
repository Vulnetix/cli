export function Footer({ user }) {
  return (
    <footer>
      <a href="https://github.com/acme/app" target="_blank">GitHub</a>
      <a href={user.website} target="_blank" rel="noopener noreferrer">Website</a>
      <a href={user.blog} rel="noreferrer" target="_blank">Blog</a>
      <a href={docsUrl} target="_self">Docs</a>
      <a href="/help" target="_blank">Help</a>
      <button onClick={() => setOpen(true)} target="_blank">x</button>
    </footer>
  );
}
