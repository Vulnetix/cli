import { useGoogleReCaptcha } from '@@sample:r[e]ac[t][-]g[o]og[l]e[-][r]ec[a]pt[c]ha[-]v3@@';

export function Login() {
  const { executeRecaptcha } = useGoogleReCaptcha();
  async function submit() {
    const token = await executeRecaptcha!('login');
    await fetch('/api/login', { method: 'POST', body: JSON.stringify({ token }) });
  }
  return <button onClick={submit}>Log in</button>;
}
