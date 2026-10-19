import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export function GET() {
  const configured = process.env.API_BASE_URL;
  if (!configured) {
    return NextResponse.json({ detail: "API_BASE_URL is not configured." }, { status: 503 });
  }

  try {
    const apiUrl = new URL(configured);
    if (!["http:", "https:"].includes(apiUrl.protocol) || apiUrl.username || apiUrl.password
        || apiUrl.pathname !== "/" || apiUrl.search || apiUrl.hash) {
      throw new Error("Unsupported API URL");
    }
    return NextResponse.json({ apiBaseUrl: apiUrl.origin });
  } catch {
    return NextResponse.json({ detail: "API_BASE_URL is invalid." }, { status: 500 });
  }
}
