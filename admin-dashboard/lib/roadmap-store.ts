/**
 * In-memory roadmap store.
 *
 * Votes and status overrides are held in module-level Maps so they survive
 * across requests within a single server process. In production you would
 * replace this with a database (e.g. Postgres via Prisma).
 *
 * The base vote counts come from public/roadmap.json; overrides layer on top.
 */

import {
  loadRoadmapItems,
  type RoadmapItem,
  type RoadmapStatus,
} from "./roadmap";

// userId → Set<itemId>  (which items the user has voted for)
const userVotes = new Map<string, Set<string>>();

// itemId → vote delta (relative to the JSON baseline)
const voteDeltas = new Map<string, number>();

// itemId → status override
const statusOverrides = new Map<string, RoadmapStatus>();

export interface RoadmapItemWithMeta extends RoadmapItem {
  hasVoted: boolean;
}

export function getItems(userId: string | null): RoadmapItemWithMeta[] {
  const base = loadRoadmapItems();
  const voted = userId
    ? (userVotes.get(userId) ?? new Set<string>())
    : new Set<string>();

  return base.map((item) => ({
    ...item,
    votes: item.votes + (voteDeltas.get(item.id) ?? 0),
    status: statusOverrides.get(item.id) ?? item.status,
    hasVoted: voted.has(item.id),
  }));
}

export type VoteResult =
  | { votes: number; hasVoted: boolean }
  | { error: string };

export function toggleVote(userId: string, itemId: string): VoteResult {
  const base = loadRoadmapItems();
  if (!base.find((i) => i.id === itemId)) {
    return { error: "Item not found" };
  }

  if (!userVotes.has(userId)) {
    userVotes.set(userId, new Set());
  }
  const voted = userVotes.get(userId)!;

  const delta = voteDeltas.get(itemId) ?? 0;
  const baseVotes = base.find((i) => i.id === itemId)!.votes;

  if (voted.has(itemId)) {
    voted.delete(itemId);
    voteDeltas.set(itemId, delta - 1);
    return { votes: baseVotes + delta - 1, hasVoted: false };
  } else {
    voted.add(itemId);
    voteDeltas.set(itemId, delta + 1);
    return { votes: baseVotes + delta + 1, hasVoted: true };
  }
}

export function setStatus(itemId: string, status: RoadmapStatus): boolean {
  const base = loadRoadmapItems();
  if (!base.find((i) => i.id === itemId)) return false;
  statusOverrides.set(itemId, status);
  return true;
}
