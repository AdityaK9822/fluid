interface CategoryBadgeProps {
  category: string;
}

function toneForCategory(category: string): string {
  const value = category.toLowerCase();

  if (value.includes("swap")) {
    return "bg-violet-50 text-violet-700 ring-violet-200";
  }

  if (value.includes("nft")) {
    return "bg-fuchsia-50 text-fuchsia-700 ring-fuchsia-200";
  }

  if (value.includes("soroban") || value.includes("contract")) {
    return "bg-sky-50 text-sky-700 ring-sky-200";
  }

  if (value.includes("transfer") || value.includes("funding")) {
    return "bg-emerald-50 text-emerald-700 ring-emerald-200";
  }

  if (value.includes("trustline") || value.includes("config")) {
    return "bg-amber-50 text-amber-700 ring-amber-200";
  }

  return "bg-slate-100 text-slate-700 ring-slate-200";
}

export function CategoryBadge({ category }: CategoryBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${toneForCategory(
        category,
      )}`}
    >
      {category}
    </span>
  );
}
