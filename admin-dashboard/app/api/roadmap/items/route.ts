import { NextRequest, NextResponse } from "next/server";
import { getItems } from "@/lib/roadmap-store";
import { verifySsoToken } from "@/lib/roadmap";

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("token");
  const userId = token ? verifySsoToken(token) : null;
  return NextResponse.json({ items: getItems(userId) });
}
