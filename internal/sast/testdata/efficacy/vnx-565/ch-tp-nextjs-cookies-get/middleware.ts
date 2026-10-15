import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
~>  if (request.cookies.get('isAdmin')?.value === 'true') {
    return NextResponse.next();
  }
  return NextResponse.redirect(new URL('/login', request.url));
}
