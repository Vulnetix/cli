export function Profile({ user }) {
  return (
    <div>
~>      <a href={user.website} target="_blank">Website</a>
      <a
        className="link"
        href={`${user.homepage}/about`}
~>        target="_blank"
      >
        About
      </a>
~>      <Link href={user.blog} target={'_blank'} rel="nofollow">Blog</Link>
      <a href={`https://social.example/${user.handle}`} target="_blank">Social</a>
    </div>
  );
}
