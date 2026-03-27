export type DashboardSignerStatus =
  | "Active"
  | "Low Balance"
  | "Sequence Error"
  | "Inactive";

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
  status: DashboardSignerStatus;
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

export interface TenantUsageRow {
  tenant: string;
  txCount: number;
  totalCostStroops: number;
  successCount: number;
  failedCount: number;
}

export interface ApiKey {
  id: string;
  key: string;
  prefix: string;
  tenantId: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export type WebhookEventType = "tx.success" | "tx.failed" | "balance.low";

export interface WebhookTenantSettings {
  tenantId: string;
  tenantName: string | null;
  webhookUrl: string | null;
  eventTypes: WebhookEventType[];
  updatedAt: string | null;
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
