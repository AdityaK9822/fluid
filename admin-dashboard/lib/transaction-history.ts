import "server-only";

import type {
  TransactionHistoryPageData,
  TransactionHistoryQuery,
  TransactionHistoryRow,
  TransactionHistorySort,
  TransactionStatus,
} from "@/components/dashboard/types";

interface TransactionsApiResponse {
  transactions?: Array<{
    hash: string;
    tenantId: string;
    status: TransactionStatus;
    createdAt: string;
    updatedAt: string;
  }>;
}

type SearchParamsShape =
  | Record<string, string | string[] | undefined>
  | URLSearchParams
  | undefined;

const DEFAULT_PAGE_SIZE = 6;

const SAMPLE_ROWS: TransactionHistoryRow[] = [
  ["2026-03-26T09:38:00.000Z", "e9173ee8b19e004b44ab22d0c1fa4c8029cb6dd4f70b2fdc0e1d897580f48421", "success", 18240, "anchor-west"],
  ["2026-03-26T09:31:00.000Z", "7f84c335eab0ce7c6b9d662a6bdaee8b5811a0aa73b61ca7f0fc262ec9dbed8e", "submitted", 24410, "mobile-wallet"],
  ["2026-03-26T09:27:00.000Z", "54ac50f1d4f33bf3fa0f27c48ceaf7125b1d74c7b3ef97d90df5a8e01db2fc1d", "failed", 39870, "market-maker"],
  ["2026-03-26T09:22:00.000Z", "11f88f20843491bca1e0d5354e31d9f7089e0a88c8a0a6248a99f1d3c8f54f6d", "success", 17600, "anchor-west"],
  ["2026-03-26T09:18:00.000Z", "8d6ca55f4cdb99eb91f68562202d447dadbef36f36fd84721380d72a6f390f13", "success", 12950, "risk-engine"],
  ["2026-03-26T09:11:00.000Z", "1fd7c10f5b5ce0ff6d679f2f7d94a4f3b6ab6679b4ea31ec6b5d55a9eab3da8c", "pending", 30120, "custody-labs"],
  ["2026-03-26T08:58:00.000Z", "ad6d0e6f5b718e1e29d05887769234d5b2d5b6f79a1223c6dbd36a72112c862e", "success", 15000, "mobile-wallet"],
  ["2026-03-26T08:44:00.000Z", "f9a2573b26f7c6c1f4206f9cf9192daab26ed4760b9db8a894f3bbfbc4ca6d0c", "failed", 41760, "market-maker"],
  ["2026-03-26T08:29:00.000Z", "960fbb8e4fd0994c1556250c2db3cbc12038fd60d0c72d4fa0a0ee4ac2d27595", "submitted", 26610, "anchor-east"],
  ["2026-03-26T08:14:00.000Z", "0f6dc3c13c88c07c6c52ba4aac1e5370af1f97aa2483dbef8e826a3de0f66149", "success", 14120, "api-gateway"],
  ["2026-03-26T07:52:00.000Z", "d817ca4ef38c29ee6b1b12d8e30162bce5ab45fb4892a73801f6ec83bdfc10b1", "failed", 39005, "custody-labs"],
  ["2026-03-26T07:37:00.000Z", "4b3c76c3d6a3e6bf52762d474d58f4dd7fa12c18da1e35d9b765842533c8f0a8", "success", 13340, "anchor-west"],
].map(([timestamp, innerHash, status, costStroops, tenant], index) => ({
  id: `sample-tx-${index + 1}`,
  timestamp,
  innerHash,
  status,
  costStroops,
  tenant,
}));

function getBaseUrl() {
  const value = process.env.FLUID_SERVER_URL?.trim();
  return value ? value.replace(/\/$/, "") : null;
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }

  return response.json() as Promise<T>;
}

function deterministicCost(hash: string) {
  const seed = Number.parseInt(hash.slice(0, 6), 16);
  return 12000 + (seed % 32000);
}

function parseSearchParam(
  searchParams: SearchParamsShape,
  key: string,
): string | undefined {
  if (!searchParams) {
    return undefined;
  }

  if (searchParams instanceof URLSearchParams) {
    return searchParams.get(key) ?? undefined;
  }

  const value = searchParams[key];
  return Array.isArray(value) ? value[0] : value;
}

export function parseTransactionHistoryQuery(
  searchParams: SearchParamsShape,
): TransactionHistoryQuery {
  const rawPage = Number.parseInt(parseSearchParam(searchParams, "page") ?? "1", 10);
  const rawPageSize = Number.parseInt(
    parseSearchParam(searchParams, "pageSize") ?? `${DEFAULT_PAGE_SIZE}`,
    10,
  );
  const rawSort = parseSearchParam(searchParams, "sort") ?? "time_desc";
  const search = (parseSearchParam(searchParams, "q") ?? "").trim();

  const sort: TransactionHistorySort = [
    "time_desc",
    "time_asc",
    "cost_desc",
    "cost_asc",
  ].includes(rawSort)
    ? (rawSort as TransactionHistorySort)
    : "time_desc";

  return {
    page: Number.isFinite(rawPage) && rawPage > 0 ? rawPage : 1,
    pageSize:
      Number.isFinite(rawPageSize) && rawPageSize > 0 && rawPageSize <= 20
        ? rawPageSize
        : DEFAULT_PAGE_SIZE,
    search,
    sort,
  };
}

function sortRows(rows: TransactionHistoryRow[], sort: TransactionHistorySort) {
  return [...rows].sort((left, right) => {
    if (sort === "cost_desc") {
      return right.costStroops - left.costStroops;
    }

    if (sort === "cost_asc") {
      return left.costStroops - right.costStroops;
    }

    const leftTime = new Date(left.timestamp).getTime();
    const rightTime = new Date(right.timestamp).getTime();

    return sort === "time_asc" ? leftTime - rightTime : rightTime - leftTime;
  });
}

function filterRows(rows: TransactionHistoryRow[], search: string) {
  if (!search) {
    return rows;
  }

  const needle = search.toLowerCase();
  return rows.filter((row) => {
    return (
      row.innerHash.toLowerCase().includes(needle) ||
      row.tenant.toLowerCase().includes(needle) ||
      row.status.toLowerCase().includes(needle)
    );
  });
}

function paginateRows(rows: TransactionHistoryRow[], page: number, pageSize: number) {
  const totalRows = rows.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;

  return {
    rows: rows.slice(start, start + pageSize),
    page: safePage,
    totalRows,
    totalPages,
  };
}

async function fetchLiveRows(): Promise<TransactionHistoryRow[]> {
  const baseUrl = getBaseUrl();
  if (!baseUrl) {
    throw new Error("No server URL configured");
  }

  const response = await fetchJson<TransactionsApiResponse>(`${baseUrl}/test/transactions`);

  return (response.transactions ?? []).map((transaction, index) => ({
    id: `live-tx-${index + 1}`,
    timestamp: transaction.updatedAt ?? transaction.createdAt,
    innerHash: transaction.hash,
    status: transaction.status,
    costStroops: deterministicCost(transaction.hash),
    tenant: transaction.tenantId,
  }));
}

export async function getTransactionHistoryPageData(
  query: TransactionHistoryQuery,
): Promise<TransactionHistoryPageData> {
  const source = getBaseUrl() ? "live" : "sample";

  let baseRows = SAMPLE_ROWS;
  if (source === "live") {
    try {
      baseRows = await fetchLiveRows();
    } catch {
      baseRows = SAMPLE_ROWS;
    }
  }

  const filtered = filterRows(baseRows, query.search);
  const sorted = sortRows(filtered, query.sort);
  const paginated = paginateRows(sorted, query.page, query.pageSize);

  return {
    rows: paginated.rows,
    page: paginated.page,
    pageSize: query.pageSize,
    totalRows: paginated.totalRows,
    totalPages: paginated.totalPages,
    sort: query.sort,
    search: query.search,
    source: source === "live" && baseRows !== SAMPLE_ROWS ? "live" : "sample",
  };
}

export function getTransactionHistoryPreviewData() {
  return getTransactionHistoryPageData({
    page: 1,
    pageSize: DEFAULT_PAGE_SIZE,
    search: "",
    sort: "time_desc",
  });
}
