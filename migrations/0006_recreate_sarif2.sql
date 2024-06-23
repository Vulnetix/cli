DROP TABLE IF EXISTS "sarif";
CREATE TABLE "sarif" (
    "sarifId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "fullName" TEXT,
    "memberEmail" TEXT NOT NULL,
    "commitSha" TEXT,
    "ref" TEXT,
    "createdAt" INTEGER NOT NULL,
    "resultsCount" INTEGER NOT NULL,
    "rulesCount" INTEGER NOT NULL,
    "toolName" TEXT,
    "toolVersion" TEXT,
    "analysisKey" TEXT,
    "warning" TEXT
);

CREATE UNIQUE INDEX "sarif_sarifId_key" ON "sarif"("sarifId");
