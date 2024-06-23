DROP TABLE IF EXISTS "sarif";
CREATE TABLE "sarif" (
    "sarifId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "ref" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "resultsCount" INTEGER NOT NULL,
    "rulesCount" INTEGER NOT NULL,
    "toolName" TEXT,
    "toolVersion" TEXT,
    "analysisKey" TEXT NOT NULL,
    "warning" TEXT
);

CREATE UNIQUE INDEX "sarif_sarifId_key" ON "sarif"("sarifId");
