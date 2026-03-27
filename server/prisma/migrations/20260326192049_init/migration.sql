/*
  Warnings:

  - You are about to drop the column `lastError` on the `WebhookDelivery` table. All the data in the column will be lost.
  - You are about to drop the column `nextAttempt` on the `WebhookDelivery` table. All the data in the column will be lost.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_WebhookDelivery" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "retryCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "WebhookDelivery_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_WebhookDelivery" ("createdAt", "id", "payload", "retryCount", "status", "tenantId", "updatedAt", "url") SELECT "createdAt", "id", "payload", "retryCount", "status", "tenantId", "updatedAt", "url" FROM "WebhookDelivery";
DROP TABLE "WebhookDelivery";
ALTER TABLE "new_WebhookDelivery" RENAME TO "WebhookDelivery";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
