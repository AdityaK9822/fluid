import { auth } from "@/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { loadRoadmapItems } from "@/lib/roadmap";
import { RoadmapStatusManager } from "@/components/dashboard/RoadmapStatusManager";

export default async function AdminRoadmapPage() {
  const session = await auth();
  if (!session) redirect("/login");

  const items = loadRoadmapItems();

  return (
    <div className="min-h-screen bg-slate-100">
      <div className="border-b border-slate-200 bg-white/90 backdrop-blur">
        <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between py-6">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.25em] text-sky-600">
                Fluid Admin
              </p>
              <h1 className="mt-1 text-2xl font-bold text-slate-900">
                Roadmap Management
              </h1>
            </div>
            <Link
              href="/admin/dashboard"
              className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-50"
            >
              ← Dashboard
            </Link>
          </div>
        </div>
      </div>

      <main className="mx-auto max-w-4xl px-4 py-8 sm:px-6 lg:px-8">
        <RoadmapStatusManager items={items} />
      </main>
    </div>
  );
}
