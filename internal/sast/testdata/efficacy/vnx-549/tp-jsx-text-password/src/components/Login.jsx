export function Login({ onChange }) {
  return (
    <form>
~>      <input type="text" name="password" value={pw} onChange={onChange} />
    </form>
  );
}
