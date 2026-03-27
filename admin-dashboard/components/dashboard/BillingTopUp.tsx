"use client";

import { useState } from "react";
import { CreditCard, Loader2 } from "lucide-react";

const TIERS = [
  { amountCents: 500,  label: "$5",  description: "100 XLM quota" },
  { amountCents: 2000, label: "$20", description: "500 XLM quota" },
  { amountCents: 5000, label: "$50", description: "1,500 XLM quota" },
];

interface Props {
  tenantId: string;
}

export function BillingTopUp({ tenantId }: Props) {
  const [selected, setSelected] = useState<number>(2000);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCheckout() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/billing/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId, amountCents: selected }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to create checkout session");
      window.location.href = data.url;
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center gap-2 mb-4">
        <CreditCard className="h-5 w-5 text-sky-600" />
        <h2 className="text-lg font-semibold text-slate-900">Top-up Quota</h2>
      </div>
      <p className="text-sm text-slate-500 mb-5">
        Purchase additional XLM sponsorship quota using a credit card via Stripe.
      </p>

      <div className="grid grid-cols-3 gap-3 mb-5">
        {TIERS.map((tier) => (
          <button
            key={tier.amountCents}
            onClick={() => setSelected(tier.amountCents)}
            className={`rounded-xl border-2 p-4 text-left transition ${
              selected === tier.amountCents
                ? "border-sky-500 bg-sky-50"
                : "border-slate-200 hover:border-slate-300"
            }`}
          >
            <div className="text-xl font-bold text-slate-900">{tier.label}</div>
            <div className="text-xs text-slate-500 mt-1">{tier.description}</div>
          </button>
        ))}
      </div>

      {error && (
        <p className="mb-4 rounded-lg bg-red-50 px-4 py-2 text-sm text-red-600">{error}</p>
      )}

      <button
        onClick={handleCheckout}
        disabled={loading}
        className="flex w-full items-center justify-center gap-2 rounded-full bg-sky-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:opacity-60"
      >
        {loading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <CreditCard className="h-4 w-4" />
        )}
        {loading ? "Redirecting to Stripe…" : "Pay with Card"}
      </button>
    </div>
  );
}
