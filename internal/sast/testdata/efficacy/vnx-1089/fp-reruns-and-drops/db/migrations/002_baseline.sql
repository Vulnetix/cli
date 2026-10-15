CREATE UNIQUE INDEX IF NOT EXISTS "Account_email_key" ON "Account"("email");
CREATE INDEX IF NOT EXISTS "Account_org_idx" ON "Account"("org");
CREATE INDEX IF NOT EXISTS "Account_plan_idx" ON "Account"("plan");
CREATE INDEX IF NOT EXISTS "Account_region_idx" ON "Account"("region");
CREATE INDEX IF NOT EXISTS "Account_createdAt_idx" ON "Account"("createdAt");
CREATE INDEX "Account_org_plan_idx" ON "Account"("org", "plan");
CREATE INDEX "Account_org_region_idx" ON "Account"("org", "region");
CREATE INDEX "Account_org_createdAt_idx" ON "Account"("org", "createdAt");
CREATE INDEX "Account_plan_createdAt_idx" ON "Account"("plan", "createdAt");
