export function Poller({ id }) {
~>  setTimeout("refresh(" + id + ")", 1000);
~>  setInterval(`tick('${id}')`, 5000);
  return <div>polling</div>;
}
