import roadmapData from "../public/roadmap.json";
import { createHmac } from "crypto";

export type RoadmapStatus = "planned" | "in-progress" | "shipped";

export interface RoadmapItem {
  id: string;
  title: string;
  description: string;
  status: RoadmapStatus;
  category: string;
  votes: number;
  createdAt: string;
}

export interface RoadmapManifest {
  items: RoadmapItem[];
}

export function loadRoadmapItems(): RoadmapItem[] {
  return (roadmapData as RoadmapManifest).items;
}

export const STATUS_LABELS: Record<RoadmapStatus, string> = {
  planned: "Planned",
  "in-progress": "In Progress",
  shipped: "Shipped",
};

export const STATUS_COLORS: Record<RoadmapStatus, string> = {
  planned: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  "in-progress":
    "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
  shipped:
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300",
};

/**
 * Generate a short-lived SSO token so the roadmap board can identify
 * a logged-in Fluid developer without exposing their session cookie.
 *
 * Token format (HMAC-SHA256, hex): `<userId>.<exp>.<sig>`
 * where exp is a Unix timestamp (seconds).
 */
export function generateSsoToken(userId: string, ttlSeconds = 3600): string {
  const secret = process.env.ROADMAP_SSO_SECRET ?? "dev-roadmap-secret";
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `${userId}.${exp}`;
  const sig = createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

/**
 * Verify a roadmap SSO token. Returns the userId on success, null on failure.
 */
export function verifySsoToken(token: string): string | null {
  try {
    const secret = process.env.ROADMAP_SSO_SECRET ?? "dev-roadmap-secret";
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [userId, expStr, sig] = parts;
    const exp = Number(expStr);
    if (isNaN(exp) || Date.now() / 1000 > exp) return null;
    const payload = `${userId}.${expStr}`;
    const expected = createHmac("sha256", secret).update(payload).digest("hex");
    // Constant-time comparison
    if (expected.length !== sig.length) return null;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
    }
    return diff === 0 ? userId : null;
  } catch {
    return null;
  }
}
