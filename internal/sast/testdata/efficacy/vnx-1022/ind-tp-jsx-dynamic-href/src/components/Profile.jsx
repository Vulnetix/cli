import React from 'react';

export default function Profile({ user }) {
  return (
    <section>
      <h2>{user.name}</h2>
~>      <a href={user.website} target="_blank">Website</a>
    </section>
  );
}
