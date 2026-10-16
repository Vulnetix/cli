export default function Footer({ user }) {
  return (
    <footer>
      <a href="https://example.com/terms" target="_blank">Terms</a>
      <a href={user.website} target="_blank" rel="noopener noreferrer">Website</a>
      <a href={user.blog} rel="noreferrer" target="_blank">Blog</a>
      <a href={`https://github.com/${user.github}`} target="_blank">GitHub</a>
    </footer>
  );
}
