import { NextRequest, NextResponse } from "next/server";

const FLUID_SERVER_URL = process.env.FLUID_SERVER_URL ?? "http://localhost:3000";

export async function POST(req: NextRequest) {
  const body = await req.json();

  const res = await fetch(`${FLUID_SERVER_URL}/create-checkout-session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await res.json();

  if (!res.ok) {
    return NextResponse.json(data, { status: res.status });
  }

  return NextResponse.json(data);
}
