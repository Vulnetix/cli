import React from 'react';

export function Comment({ comment }) {
  return (
    <article>
      <h3>{comment.author}</h3>
~>      <div dangerouslySetInnerHTML={{ __html: comment.body }} />
    </article>
  );
}
