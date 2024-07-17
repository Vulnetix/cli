CREATE TABLE "new_spdx" (
    "spdxId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "repoName" TEXT,
    "spdxVersion" TEXT NOT NULL,
    "dataLicense" TEXT,
    "name" TEXT,
    "documentNamespace" TEXT,
    "createdAt" INTEGER NOT NULL,
    "toolName" TEXT,
    "documentDescribes" TEXT,
    "packagesJSON" TEXT,
    "relationshipsJSON" TEXT,
    "comment" TEXT
);
DROP TABLE "spdx";
ALTER TABLE "new_spdx"
    RENAME TO "spdx";
CREATE UNIQUE INDEX "spdx_spdxId_key" ON "spdx"("spdxId");
