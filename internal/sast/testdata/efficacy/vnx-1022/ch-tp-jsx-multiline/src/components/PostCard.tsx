import React from 'react';

export function PostCard({ post }: { post: { url: string; title: string } }) {
  return (
    <article>
      <a
        className="post-link"
        href={post.url}
~>        target="_blank"
      >
        {post.title}
      </a>
    </article>
  );
}
