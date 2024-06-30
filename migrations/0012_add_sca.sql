CREATE UNIQUE INDEX "integration_usage_log_key" ON "integration_usage_log"("id");
DROP TABLE IF EXISTS "findings_sca";
CREATE TABLE "findings_sca" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "memberEmail" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "detectionTitle" TEXT NOT NULL,
    "purl" TEXT,
    "cpe" TEXT,
    "packageName" TEXT NOT NULL,
    "packageVersion" TEXT,
    "fixVersion" TEXT,
    "remediation" TEXT,
    "maliciousSource" TEXT,
    "abandoned" INTEGER,
    "squattedPackage" TEXT
);
CREATE UNIQUE INDEX "findings_sca_key" ON "findings_sca"("id");
