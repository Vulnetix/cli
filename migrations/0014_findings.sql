DROP TABLE IF EXISTS "findings_sca";
CREATE TABLE "findings_sca" (
    "findingId" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "modifiedAt" INTEGER NOT NULL,
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
CREATE UNIQUE INDEX "findings_sca_findingid_key" ON "findings_sca"("findingId");
