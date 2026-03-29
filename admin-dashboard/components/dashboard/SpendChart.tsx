"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { SpendForecastData } from "@/components/dashboard/types";

interface SpendChartProps {
  forecast: SpendForecastData;
}

interface ChartPoint {
  date: string;
  historicalBalance: number | null;
  projectedBalance: number | null;
}

function formatDayLabel(value: string): string {
  const date = new Date(value);
  return date.toLocaleDateString("en-US", { month: "short", day: "2-digit" });
}

function mergeChartSeries(forecast: SpendForecastData): ChartPoint[] {
  const byDate = new Map<string, ChartPoint>();

  for (const point of forecast.historicalBalance) {
    byDate.set(point.date, {
      date: point.date,
      historicalBalance: point.balanceXlm,
      projectedBalance: null,
    });
  }

  for (const point of forecast.projectedBalance) {
    const existing = byDate.get(point.date);
    if (existing) {
      existing.projectedBalance = point.balanceXlm;
      byDate.set(point.date, existing);
      continue;
    }

    byDate.set(point.date, {
      date: point.date,
      historicalBalance: null,
      projectedBalance: point.balanceXlm,
    });
  }

  return Array.from(byDate.values()).sort((left, right) =>
    left.date.localeCompare(right.date)
  );
}

function RunwayBanner({ forecast }: SpendChartProps) {
  const warningClass = forecast.alert
    ? "border-rose-200 bg-rose-50 text-rose-700"
    : "border-emerald-200 bg-emerald-50 text-emerald-700";

  return (
    <div className={`rounded-xl border px-4 py-3 text-sm font-medium ${warningClass}`}>
      {forecast.runwayMessage}
      {forecast.alert ? " • Projected runway is below 7 days" : ""}
    </div>
  );
}

export function SpendChart({ forecast }: SpendChartProps) {
  const data = mergeChartSeries(forecast);

  const tickFormatter = (_: string, index: number) =>
    index % 5 === 0 ? formatDayLabel(data[index]?.date ?? "") : "";

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4 flex flex-col gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-sky-600">
            Analytics
          </p>
          <h2 className="mt-1 text-lg font-bold text-slate-900">Balance Runway Forecast</h2>
          <p className="mt-0.5 text-sm text-slate-500">
            Linear regression over the last 30 days of spend with projected balance curve
          </p>
        </div>
        <RunwayBanner forecast={forecast} />
      </div>

      <ResponsiveContainer width="100%" height={280}>
        <LineChart data={data} margin={{ top: 4, right: 6, left: 4, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
          <XAxis
            dataKey="date"
            tickFormatter={tickFormatter}
            tick={{ fontSize: 12, fill: "#94a3b8" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tickFormatter={(value: number) =>
              value >= 1000 ? `${(value / 1000).toFixed(1)}k` : value.toFixed(0)
            }
            tick={{ fontSize: 12, fill: "#94a3b8" }}
            axisLine={false}
            tickLine={false}
            width={48}
          />
          <Tooltip
            formatter={(value) =>
              typeof value === "number"
                ? `${value.toFixed(2)} XLM`
                : typeof value === "string"
                  ? value
                  : ""
            }
            labelFormatter={(value) =>
              new Intl.DateTimeFormat("en-US", {
                month: "long",
                day: "numeric",
                year: "numeric",
              }).format(new Date(value))
            }
          />
          <Line
            type="monotone"
            dataKey="historicalBalance"
            stroke="#0ea5e9"
            strokeWidth={2.5}
            dot={false}
            name="Historical Balance"
            connectNulls
          />
          <Line
            type="monotone"
            dataKey="projectedBalance"
            stroke="#f97316"
            strokeWidth={2.5}
            dot={false}
            strokeDasharray="6 4"
            name="Projected Balance"
            connectNulls
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
