-- CreateTable
CREATE TABLE "QuotaTopUp" (
    "id"              TEXT NOT NULL PRIMARY KEY,
    "tenantId"        TEXT NOT NULL,
    "stripeSessionId" TEXT NOT NULL,
    "amountCents"     INTEGER NOT NULL,
    "quotaStroops"    BIGINT NOT NULL,
    "status"          TEXT NOT NULL DEFAULT 'pending',
    "createdAt"       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"       DATETIME NOT NULL,
    CONSTRAINT "QuotaTopUp_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

-- CreateIndex
CREATE UNIQUE INDEX "QuotaTopUp_stripeSessionId_key" ON "QuotaTopUp"("stripeSessionId");

-- CreateIndex
CREATE INDEX "QuotaTopUp_tenantId_idx" ON "QuotaTopUp"("tenantId");

-- CreateIndex
CREATE INDEX "QuotaTopUp_status_idx" ON "QuotaTopUp"("status");
