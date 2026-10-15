import React from "react";

type Props = { article: { title: string; bodyHtml: string } };

export function Article({ article }: Props) {
  return (
    <article>
      <h1>{article.title}</h1>
~>      <section dangerouslySetInnerHTML={{ __html: article.bodyHtml }} />
    </article>
  );
}
