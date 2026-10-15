import { randomUUID } from 'crypto';

export function spin(el: HTMLElement) {
  const r = Math.random() * 360;
  const tokenCount: number = Math.floor(Math.random() * 10);
  el.style.transform = `rotate(${r}deg)`;
  const sessionToken = randomUUID();
  return { tokenCount, sessionToken, angle: r };
}
