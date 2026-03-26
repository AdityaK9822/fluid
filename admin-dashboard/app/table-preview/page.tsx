import { SignersTable, TransactionsTable } from "@/components/dashboard/ResponsiveTables";
import { getDashboardPreviewData } from "@/lib/dashboard-data";

export default function TablePreviewPage() {
  const { signers, transactions } = getDashboardPreviewData();

  return (
    <main className="min-h-screen bg-slate-100 px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-semibold uppercase tracking-[0.22em] text-sky-600">
            QA Preview
          </p>
          <h1 className="mt-2 text-3xl font-bold text-slate-900">Responsive Data Tables</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            This preview route mirrors the dashboard table components for mobile verification.
          </p>
        </section>

        <TransactionsTable transactions={transactions} />
        <SignersTable signers={signers} />
      </div>
    </main>
  );
}
