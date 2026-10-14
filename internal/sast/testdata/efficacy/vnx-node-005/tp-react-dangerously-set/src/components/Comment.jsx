export function Comment({ body }) {
~>  return <div className="comment" dangerouslySetInnerHTML={{ __html: body }} />;
}
