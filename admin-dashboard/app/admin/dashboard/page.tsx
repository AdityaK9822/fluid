import { auth } from "@/auth";
import Link from "next/link";
import { SignersTable, TransactionsTable } from "@/components/dashboard/ResponsiveTables";
import { getDashboardPageData } from "@/lib/dashboard-data";

export default async function AdminDashboard() {
  const session = await auth();
  const { signers, transactions, source } = await getDashboardPageData();

  return (
    <div className="min-h-screen bg-slate-100">
      <div className="border-b border-slate-200 bg-white/90 backdrop-blur">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 py-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.25em] text-sky-600">
                Fluid Admin
              </p>
              <h1 className="mt-2 text-3xl font-bold text-slate-900">Node Operations Dashboard</h1>
              <p className="mt-2 max-w-2xl text-sm text-slate-600">
                Transaction and signer visibility is optimized for mobile-first admin checks.
              </p>
            </div>
            <div className="flex items-center gap-4">
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                <div className="font-medium text-slate-900">{session?.user?.email}</div>
                <div>{source === "live" ? "Live server data" : "Sample dashboard data"}</div>
              </div>
              <form action="/api/auth/signout" method="POST">
                <button
                  type="submit"
                  className="rounded-full bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-700"
                >
                  Sign Out
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>

      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <section className="grid gap-4 md:grid-cols-3">
          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-medium text-slate-500">Tracked Transactions</p>
            <p className="mt-2 text-3xl font-bold text-slate-900">{transactions.length}</p>
          </div>
          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-medium text-slate-500">Signer Accounts</p>
            <p className="mt-2 text-3xl font-bold text-slate-900">{signers.length}</p>
          </div>
          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-medium text-slate-500">Mobile UX</p>
            <p className="mt-2 text-3xl font-bold text-slate-900">Expandable</p>
          </div>
        </section>

        <section className="mt-6 space-y-6">
          <div className="flex justify-end">
            <Link
              href="/admin/transactions"
              className="inline-flex min-h-10 items-center justify-center rounded-full bg-slate-900 px-4 text-sm font-semibold text-white transition hover:bg-slate-700"
            >
              Open transaction history
            </Link>
          </div>
          <TransactionsTable transactions={transactions} />
          <SignersTable signers={signers} />
        </section>
      </main>
    </div>
  );
}
