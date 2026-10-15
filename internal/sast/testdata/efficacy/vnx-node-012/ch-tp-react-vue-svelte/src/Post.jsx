export function Post({ post }) {
~>  return <article dangerouslySetInnerHTML={{ __html: post.body }} />;
}
