"use client";

import { FormEvent, useMemo, useState } from "react";

interface EstimateResponse {
  estimatedStroops: number;
  estimatedUsd: number;
  estimatedXlm: number;
  multiplierUsed: number;
  operationCount: number;
  operationTypes: string[];
  source: "openai" | "fallback";
  notes: string;
}

export function FeeEstimatorWidget() {
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EstimateResponse | null>(null);

  const disabled = useMemo(() => description.trim().length < 5 || loading, [description, loading]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const response = await fetch("/api/estimate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: description.trim() }),
      });

      const payload = (await response.json()) as EstimateResponse & { error?: string };
      if (!response.ok) {
        throw new Error(payload.error ?? `Request failed with status ${response.status}`);
      }

      setResult(payload);
    } catch (submitError: unknown) {
      setError(
        submitError instanceof Error ? submitError.message : "Failed to estimate transaction fee"
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-sky-600">AI Estimator</p>
        <h2 className="mt-1 text-lg font-bold text-slate-900">GPT Fee Estimator</h2>
        <p className="mt-0.5 text-sm text-slate-500">
          Describe your transaction and get an estimated network fee in stroops and USD.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-3">
        <label htmlFor="fee-estimator-input" className="sr-only">
          Describe your transaction
        </label>
        <textarea
          id="fee-estimator-input"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          placeholder="Describe your transaction (e.g. USDC transfer to 3 accounts via Soroban)"
          className="min-h-24 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-sky-400"
        />
        <button
          type="submit"
          disabled={disabled}
          className="inline-flex min-h-10 items-center justify-center rounded-full bg-slate-900 px-4 text-sm font-semibold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {loading ? "Estimating..." : "Estimate fee"}
        </button>
      </form>

      {error ? <p className="mt-3 text-sm text-rose-600">{error}</p> : null}

      {result ? (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          <div className="text-base font-semibold text-slate-900">
            {result.estimatedStroops.toLocaleString()} stroops ({result.estimatedXlm.toFixed(7)} XLM)
          </div>
          <div className="mt-1">Estimated USD: ${result.estimatedUsd.toFixed(6)}</div>
          <div className="mt-1">Multiplier used: {result.multiplierUsed.toFixed(1)}x</div>
          <div className="mt-1">Operation count: {result.operationCount}</div>
          <div className="mt-1">Operation types: {result.operationTypes.join(", ") || "payment"}</div>
          <div className="mt-1">Source: {result.source === "openai" ? "OpenAI" : "Fallback rules"}</div>
          <div className="mt-2 text-xs text-slate-500">{result.notes}</div>
        </div>
      ) : null}
    </div>
  );
}
