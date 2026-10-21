import { NextResponse } from "next/server";

// This is an optimistic page redirect only. Protected APIs must validate the
// opaque session and permissions server-side; cookie presence grants no access.
export function proxy(request) {
  if (!request.cookies.has("finsight_session")) {
    const signIn = new URL("/", request.url);
    signIn.searchParams.set("next", request.nextUrl.pathname);
    return NextResponse.redirect(signIn);
  }
  return NextResponse.next();
}

export const config = { matcher: ["/app/:path*"] };
