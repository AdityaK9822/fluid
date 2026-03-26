export interface DashboardTransaction {
  id: string;
  hash: string;
  amount: string;
  asset: string;
  status: "pending" | "submitted" | "success" | "failed";
  tenantId: string;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardSigner {
  id: string;
  publicKey: string;
  status: "active" | "inactive";
  balance: string;
  inFlight: number;
  totalUses: number;
  sequenceNumber: string;
}

export type TransactionStatus = "pending" | "submitted" | "success" | "failed";

export interface TransactionHistoryRow {
  id: string;
  timestamp: string;
  innerHash: string;
  status: TransactionStatus;
  costStroops: number;
  tenant: string;
}

export type TransactionHistorySort =
  | "time_desc"
  | "time_asc"
  | "cost_desc"
  | "cost_asc";

export interface TransactionHistoryQuery {
  page: number;
  pageSize: number;
  search: string;
  sort: TransactionHistorySort;
}

export interface TransactionHistoryPageData {
  rows: TransactionHistoryRow[];
  page: number;
  pageSize: number;
  totalRows: number;
  totalPages: number;
  sort: TransactionHistorySort;
  search: string;
  source: "live" | "sample";
}
