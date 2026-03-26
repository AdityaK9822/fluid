import { Tenant } from "../models/tenantStore";
import { getTenantDailySpendStroops } from "../models/transactionLedger";

export interface QuotaCheckResult {
  allowed: boolean;
  currentSpendStroops: number;
  projectedSpendStroops: number;
  dailyQuotaStroops: number;
}

export async function checkTenantDailyQuota(
  tenant: Tenant,
  feeStroops: number,
  now: Date = new Date()
): Promise<QuotaCheckResult> {
  const currentSpendStroops = await getTenantDailySpendStroops(tenant.id, now);
  const projectedSpendStroops = currentSpendStroops + feeStroops;

  return {
    allowed: projectedSpendStroops <= tenant.dailyQuotaStroops,
    currentSpendStroops,
    projectedSpendStroops,
    dailyQuotaStroops: tenant.dailyQuotaStroops,
  };
}
