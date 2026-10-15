import { v1 as uuidv1, v5 } from 'uuid';

const NS = '@@sample:1[b]67[1]a6[4][-]4[0]d5[-]49[1]e[-][9]9b[0][-]d[a]01[f]f1[f]33[4]1@@';

export function newSession() {
~>  const token = uuidv1();
  return token;
}

export function inviteFor(email) {
~>  const inviteCode = v5(email, NS);
  return inviteCode;
}
