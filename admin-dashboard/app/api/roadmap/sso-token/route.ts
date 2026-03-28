/**
 * Issues a short-lived SSO token for the roadmap board.
 * The caller must supply a `userId` query param (set by the portal page
 * after reading the NextAuth session server-side).
 *
 * In production this endpoint would be called from a Server Component or
 * Server Action so the userId comes from the verified session, not the client.
 */
import { NextRequest, NextResponse } from "next/server";
import { generateSsoToken } from "@/lib/roadmap";

export async function GET(req: NextRequest) {
  const userId = req.nextUrl.searchParams.get("userId");
  if (!userId) {
    return NextResponse.json({ error: "userId required" }, { status: 400 });
  }
  const token = generateSsoToken(userId);
  return NextResponse.json({ token });
}
