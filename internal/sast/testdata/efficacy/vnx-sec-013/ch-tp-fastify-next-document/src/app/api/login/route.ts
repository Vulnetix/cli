import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const session = await createSession(await request.json());
  const response = NextResponse.json({ ok: true });
~>  response.cookies.set('session', session.id, { secure: true, path: '/' });
  return response;
}
