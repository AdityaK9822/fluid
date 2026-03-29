-- Add transaction category for analytics and dashboard filtering
ALTER TABLE "Transaction" ADD COLUMN "category" TEXT NOT NULL DEFAULT 'Other';

-- CreateIndex
CREATE INDEX "Transaction_category_idx" ON "Transaction"("category");
