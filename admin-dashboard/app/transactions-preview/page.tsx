import { TransactionTable } from "@/components/dashboard/TransactionTable";
import { getTransactionHistoryPreviewData } from "@/lib/transaction-history";

export default async function TransactionsPreviewPage() {
  const data = await getTransactionHistoryPreviewData();

  return (
    <main className="min-h-screen bg-slate-100 px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-sm font-semibold uppercase tracking-[0.22em] text-sky-600">
            QA Preview
          </p>
          <h1 className="mt-2 text-3xl font-bold text-slate-900">Transaction History Table</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-600">
            Preview route for the paginated transaction table and pagination controls.
          </p>
        </section>

        <TransactionTable data={data} basePath="/transactions-preview" />
      </div>
    </main>
  );
}
