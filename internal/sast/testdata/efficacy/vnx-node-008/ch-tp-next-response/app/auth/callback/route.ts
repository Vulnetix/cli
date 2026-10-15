import { NextResponse, type NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  const next = request.nextUrl.searchParams.get("next");
  await exchangeCode(request);
~>  return NextResponse.redirect(next!);
}
