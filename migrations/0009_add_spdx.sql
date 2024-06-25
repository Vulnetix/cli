CREATE TABLE "spdx" (
    "spdxId" TEXT NOT NULL,
    "spdxVersion" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "repoName" TEXT,
    "name" TEXT,
    "dataLicense" TEXT,
    "documentNamespace" TEXT,
    "toolName" TEXT,
    "packageCount" INTEGER NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "comment" TEXT
);
CREATE UNIQUE INDEX "spdx_spdxId_key" ON "spdx"("spdxId");
