import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import { setStatus } from "@/lib/roadmap-store";
import { type RoadmapStatus } from "@/lib/roadmap";

const VALID_STATUSES: RoadmapStatus[] = ["planned", "in-progress", "shipped"];

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await auth();
  if (!session || session.user?.role !== "admin") {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const { status } = await req.json();

  if (!VALID_STATUSES.includes(status)) {
    return NextResponse.json({ error: "Invalid status" }, { status: 400 });
  }

  const ok = setStatus(id, status as RoadmapStatus);
  if (!ok) {
    return NextResponse.json({ error: "Item not found" }, { status: 404 });
  }

  return NextResponse.json({ id, status });
}
