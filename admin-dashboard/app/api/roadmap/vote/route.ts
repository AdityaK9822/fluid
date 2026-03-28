import { NextRequest, NextResponse } from "next/server";
import { toggleVote } from "@/lib/roadmap-store";
import { verifySsoToken } from "@/lib/roadmap";

export async function POST(req: NextRequest) {
  const { itemId, token } = await req.json();

  if (!token) {
    return NextResponse.json(
      { error: "Authentication required" },
      { status: 401 },
    );
  }

  const userId = verifySsoToken(token);
  if (!userId) {
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 401 },
    );
  }

  if (!itemId || typeof itemId !== "string") {
    return NextResponse.json({ error: "itemId required" }, { status: 400 });
  }

  const result = toggleVote(userId, itemId);
  if ("error" in result) {
    return NextResponse.json(result, { status: 404 });
  }

  return NextResponse.json(result);
}
