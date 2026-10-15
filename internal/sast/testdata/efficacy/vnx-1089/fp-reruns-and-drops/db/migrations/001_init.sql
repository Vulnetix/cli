CREATE TABLE IF NOT EXISTS "Account" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "org" TEXT,
    "plan" TEXT,
    "region" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Account_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "Account_email_key" ON "Account"("email");
CREATE INDEX IF NOT EXISTS "Account_org_idx" ON "Account"("org");
CREATE INDEX IF NOT EXISTS "Account_plan_idx" ON "Account"("plan");
CREATE INDEX IF NOT EXISTS "Account_region_idx" ON "Account"("region");
CREATE INDEX IF NOT EXISTS "Account_createdAt_idx" ON "Account"("createdAt");
