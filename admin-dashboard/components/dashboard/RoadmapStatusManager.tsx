"use client";

import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import { CheckCircle, Clock, Rocket } from "lucide-react";
import {
  STATUS_COLORS,
  STATUS_LABELS,
  type RoadmapStatus,
} from "@/lib/roadmap";
import { cn } from "@/lib/utils";

interface RoadmapItem {
  id: string;
  title: string;
  status: RoadmapStatus;
  category: string;
  votes: number;
}

const STATUSES: RoadmapStatus[] = ["planned", "in-progress", "shipped"];

const STATUS_ICONS: Record<RoadmapStatus, LucideIcon> = {
  planned: Clock,
  "in-progress": Rocket,
  shipped: CheckCircle,
};

interface Props {
  items: RoadmapItem[];
}

export function RoadmapStatusManager({ items }: Props) {
  const [localItems, setLocalItems] = useState(items);
  const [saving, setSaving] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  async function updateStatus(id: string, status: RoadmapStatus) {
    setSaving(id);
    setErrors((e) => ({ ...e, [id]: "" }));
    try {
      const res = await fetch(`/api/admin/roadmap/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (!res.ok) {
        const data = await res.json();
        setErrors((e) => ({ ...e, [id]: data.error ?? "Failed to update" }));
        return;
      }
      setLocalItems((prev) =>
        prev.map((i) => (i.id === id ? { ...i, status } : i)),
      );
    } catch {
      setErrors((e) => ({ ...e, [id]: "Network error" }));
    } finally {
      setSaving(null);
    }
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 px-6 py-4">
        <h2 className="text-lg font-semibold text-slate-900">Roadmap Status</h2>
        <p className="mt-0.5 text-sm text-slate-500">
          Update the status of each roadmap item. Changes are reflected
          immediately on the public board.
        </p>
      </div>

      <ul className="divide-y divide-slate-100" role="list">
        {localItems.map((item) => {
          const Icon = STATUS_ICONS[item.status];
          return (
            <li
              key={item.id}
              className="flex flex-col gap-3 px-6 py-4 sm:flex-row sm:items-center sm:gap-6"
            >
              {/* Info */}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-900">
                    {item.title}
                  </span>
                  <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-500">
                    {item.category}
                  </span>
                  <span className="text-xs text-slate-400">
                    {item.votes} votes
                  </span>
                </div>
                <div className="mt-1 flex items-center gap-1.5">
                  <Icon className="h-3.5 w-3.5 text-slate-400" aria-hidden />
                  <span
                    className={cn(
                      "rounded-full px-2 py-0.5 text-[11px] font-semibold",
                      STATUS_COLORS[item.status],
                    )}
                  >
                    {STATUS_LABELS[item.status]}
                  </span>
                </div>
              </div>

              {/* Status selector */}
              <div className="flex flex-wrap items-center gap-2">
                {STATUSES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    disabled={saving === item.id}
                    onClick={() => updateStatus(item.id, s)}
                    aria-pressed={item.status === s}
                    className={cn(
                      "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                      item.status === s
                        ? "border-slate-900 bg-slate-900 text-white"
                        : "border-slate-200 bg-white text-slate-600 hover:border-slate-400",
                      saving === item.id && "cursor-not-allowed opacity-50",
                    )}
                  >
                    {STATUS_LABELS[s]}
                  </button>
                ))}
                {errors[item.id] && (
                  <span className="text-xs text-red-500">
                    {errors[item.id]}
                  </span>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
