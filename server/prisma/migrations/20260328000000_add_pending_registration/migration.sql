-- CreateTable: PendingRegistration
-- Tracks developer sign-up requests pending email verification.
CREATE TABLE "PendingRegistration" (
    "id"             TEXT     NOT NULL,
    "email"          TEXT     NOT NULL,
    "projectName"    TEXT     NOT NULL,
    "intendedUse"    TEXT     NOT NULL,
    "token"          TEXT     NOT NULL,
    "tokenExpiresAt" DATETIME NOT NULL,
    "status"         TEXT     NOT NULL DEFAULT 'pending',
    "createdAt"      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt"      DATETIME NOT NULL,

    CONSTRAINT "PendingRegistration_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PendingRegistration_email_key" ON "PendingRegistration"("email");

-- CreateIndex
CREATE UNIQUE INDEX "PendingRegistration_token_key" ON "PendingRegistration"("token");

-- CreateIndex
CREATE INDEX "PendingRegistration_token_idx"  ON "PendingRegistration"("token");

-- CreateIndex
CREATE INDEX "PendingRegistration_status_idx" ON "PendingRegistration"("status");
