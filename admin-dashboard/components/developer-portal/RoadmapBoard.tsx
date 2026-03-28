"use client";

import { motion } from "framer-motion";
import { ChevronUp, ExternalLink, Loader2, Map } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  STATUS_COLORS,
  STATUS_LABELS,
  type RoadmapStatus,
} from "@/lib/roadmap";
import { cn } from "@/lib/utils";

interface RoadmapItem {
  id: string;
  title: string;
  description: string;
  status: RoadmapStatus;
  category: string;
  votes: number;
  hasVoted: boolean;
}

const STATUSES: RoadmapStatus[] = ["planned", "in-progress", "shipped"];

export function RoadmapBoard() {
  const [items, setItems] = useState<RoadmapItem[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeStatus, setActiveStatus] = useState<RoadmapStatus | "all">(
    "all",
  );
  const [votingId, setVotingId] = useState<string | null>(null);

  // Fetch SSO token (identifies the current browser session as a voter)
  useEffect(() => {
    const stored = sessionStorage.getItem("roadmap_token");
    if (stored) {
      setToken(stored);
      return;
    }
    // Generate an anonymous-but-stable voter ID for this browser session
    const anonId = `anon-${Math.random().toString(36).slice(2)}`;
    fetch(`/api/roadmap/sso-token?userId=${encodeURIComponent(anonId)}`)
      .then((r) => r.json())
      .then((d) => {
        if (d.token) {
          sessionStorage.setItem("roadmap_token", d.token);
          setToken(d.token);
        }
      })
      .catch(() => {});
  }, []);

  const fetchItems = useCallback(async (t: string | null) => {
    const url = t
      ? `/api/roadmap/items?token=${encodeURIComponent(t)}`
      : "/api/roadmap/items";
    const res = await fetch(url);
    const data = await res.json();
    setItems(data.items ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchItems(token);
  }, [token, fetchItems]);

  async function handleVote(itemId: string) {
    if (!token || votingId) return;
    setVotingId(itemId);
    try {
      const res = await fetch("/api/roadmap/vote", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ itemId, token }),
      });
      if (res.ok) {
        const { votes, hasVoted } = await res.json();
        setItems((prev) =>
          prev.map((i) => (i.id === itemId ? { ...i, votes, hasVoted } : i)),
        );
      }
    } finally {
      setVotingId(null);
    }
  }

  const filtered =
    activeStatus === "all"
      ? items
      : items.filter((i) => i.status === activeStatus);

  const sorted = [...filtered].sort((a, b) => b.votes - a.votes);

  return (
    <div className="flex flex-1 flex-col bg-background text-foreground">
      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section
        className="relative isolate overflow-hidden border-b border-border/80"
        aria-labelledby="roadmap-heading"
      >
        <div
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,hsl(var(--primary)/0.15),transparent)]"
          aria-hidden
        />
        <div className="relative mx-auto max-w-7xl px-4 pb-20 pt-16 sm:px-6 sm:pb-28 sm:pt-24 lg:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
              className="mb-4 text-sm font-semibold uppercase tracking-widest text-primary"
            >
              Public roadmap
            </motion.p>
            <motion.h1
              id="roadmap-heading"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                delay: 0.06,
                duration: 0.45,
                ease: [0.22, 1, 0.36, 1],
              }}
              className="text-4xl font-extrabold tracking-tight sm:text-5xl md:text-6xl"
            >
              Shape what we build next
            </motion.h1>
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                delay: 0.12,
                duration: 0.45,
                ease: [0.22, 1, 0.36, 1],
              }}
              className="mt-6 text-lg text-muted-foreground sm:text-xl"
            >
              Upvote the features that matter most to you. The community's votes
              directly influence our sprint priorities.
            </motion.p>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                delay: 0.18,
                duration: 0.45,
                ease: [0.22, 1, 0.36, 1],
              }}
              className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row"
            >
              <Button
                size="lg"
                className="min-w-[200px] text-base shadow-lg"
                asChild
              >
                <Link href="/login">Sign in to vote</Link>
              </Button>
              <Button size="lg" variant="outline" asChild>
                <Link href="/">Back to portal</Link>
              </Button>
            </motion.div>
          </div>
        </div>
      </section>

      {/* ── Filter tabs ───────────────────────────────────────────────────── */}
      <section className="mx-auto w-full max-w-7xl px-4 pt-10 sm:px-6 lg:px-8">
        <div
          className="flex flex-wrap gap-2"
          role="group"
          aria-label="Filter by status"
        >
          <StatusTab
            label="All"
            active={activeStatus === "all"}
            onClick={() => setActiveStatus("all")}
          />
          {STATUSES.map((s) => (
            <StatusTab
              key={s}
              label={STATUS_LABELS[s]}
              active={activeStatus === s}
              onClick={() => setActiveStatus(s)}
            />
          ))}
        </div>
      </section>

      {/* ── Items ─────────────────────────────────────────────────────────── */}
      <section
        className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8"
        aria-label="Roadmap items"
      >
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2
              className="h-8 w-8 animate-spin text-muted-foreground"
              aria-label="Loading"
            />
          </div>
        ) : sorted.length === 0 ? (
          <p className="py-16 text-center text-sm text-muted-foreground">
            No items in this category yet.
          </p>
        ) : (
          <div className="space-y-3">
            {sorted.map((item, index) => (
              <RoadmapCard
                key={item.id}
                item={item}
                index={index}
                onVote={handleVote}
                isVoting={votingId === item.id}
                canVote={Boolean(token)}
              />
            ))}
          </div>
        )}
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer
        className="mt-auto border-t border-border bg-card/50"
        role="contentinfo"
      >
        <div className="mx-auto flex max-w-7xl flex-col gap-8 px-4 py-12 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
          <div>
            <p className="text-sm font-semibold text-foreground">Fluid</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Fee sponsorship infrastructure for Stellar developers.
            </p>
          </div>
          <nav className="flex flex-wrap gap-x-8 gap-y-3" aria-label="Footer">
            <Link
              href="/"
              className="text-sm font-medium text-primary hover:underline"
            >
              Developer portal
            </Link>
            <Link
              href="/plugins"
              className="text-sm font-medium text-primary hover:underline"
            >
              Plugin marketplace
            </Link>
            <Link
              href="/forum"
              className="text-sm font-medium text-primary hover:underline"
            >
              Community forum
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}

// ── RoadmapCard ──────────────────────────────────────────────────────────────

interface RoadmapCardProps {
  item: RoadmapItem;
  index: number;
  onVote: (id: string) => void;
  isVoting: boolean;
  canVote: boolean;
}

function RoadmapCard({
  item,
  index,
  onVote,
  isVoting,
  canVote,
}: RoadmapCardProps) {
  return (
    <motion.article
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-20px" }}
      transition={{ delay: index * 0.04, duration: 0.4 }}
      className="flex items-start gap-4 rounded-2xl border border-border bg-card p-5 shadow-sm transition-colors hover:border-primary/30 hover:shadow-md"
      aria-label={item.title}
    >
      {/* Vote button */}
      <button
        type="button"
        onClick={() => onVote(item.id)}
        disabled={!canVote || isVoting}
        aria-label={`${item.hasVoted ? "Remove vote from" : "Vote for"} ${item.title} — ${item.votes} votes`}
        aria-pressed={item.hasVoted}
        className={cn(
          "flex shrink-0 flex-col items-center gap-0.5 rounded-xl border px-3 py-2 text-xs font-bold transition-all",
          item.hasVoted
            ? "border-primary bg-primary text-primary-foreground"
            : "border-border bg-muted/50 text-muted-foreground hover:border-primary/50 hover:text-foreground",
          (!canVote || isVoting) && "cursor-not-allowed opacity-60",
        )}
      >
        {isVoting ? (
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
        ) : (
          <ChevronUp className="h-4 w-4" aria-hidden />
        )}
        <span>{item.votes}</span>
      </button>

      {/* Content */}
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-semibold leading-tight text-foreground">
            {item.title}
          </h3>
          <span
            className={cn(
              "rounded-full px-2.5 py-0.5 text-[11px] font-semibold",
              STATUS_COLORS[item.status],
            )}
          >
            {STATUS_LABELS[item.status]}
          </span>
          <span className="rounded-full bg-muted px-2.5 py-0.5 text-[11px] font-medium text-muted-foreground">
            {item.category}
          </span>
        </div>
        <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
          {item.description}
        </p>
      </div>
    </motion.article>
  );
}

// ── StatusTab ────────────────────────────────────────────────────────────────

function StatusTab({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-full border px-4 py-1.5 text-sm font-medium transition-colors",
        active
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border bg-card text-muted-foreground hover:border-primary/40 hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}
