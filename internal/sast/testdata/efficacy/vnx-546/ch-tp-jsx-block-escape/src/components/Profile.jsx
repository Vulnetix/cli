export function Profile({ user }) {
  return (
    <section>
~>      {/* TODO: escape the bio before rendering, it is user supplied */}
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </section>
  );
}
