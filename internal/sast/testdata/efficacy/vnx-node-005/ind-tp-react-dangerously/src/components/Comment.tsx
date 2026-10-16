import React from 'react';

type Props = { body: string };

export function Comment({ body }: Props) {
  return (
    <article className="comment">
~>      <div dangerouslySetInnerHTML={{ __html: body }} />
    </article>
  );
}
