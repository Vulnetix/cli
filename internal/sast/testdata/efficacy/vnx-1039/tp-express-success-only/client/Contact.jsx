import { useGoogleReCaptcha } from '@@sample:r[e]ac[t][-]g[o]og[l]e[-][r]ec[a]pt[c]ha[-]v3@@';

export function Contact() {
  const { executeRecaptcha } = useGoogleReCaptcha();
  return <button onClick={async () => send(await executeRecaptcha('contact'))}>Send</button>;
}
