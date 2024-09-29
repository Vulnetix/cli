CREATE TABLE "new_cdx" (
    "cdxId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "repoName" TEXT,
    "cdxVersion" TEXT NOT NULL,
    "serialNumber" TEXT,
    "name" TEXT,
    "version" TEXT,
    "createdAt" INTEGER NOT NULL,
    "toolName" TEXT,
    "externalReferencesCount" INTEGER NOT NULL,
    "componentsCount" INTEGER NOT NULL,
    "dependenciesCount" INTEGER NOT NULL
);
DROP TABLE "cdx";
ALTER TABLE "new_cdx" RENAME TO "cdx";
CREATE UNIQUE INDEX "cdx_cdxId_key" ON "cdx"("cdxId");

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
    "packagesCount" INTEGER NOT NULL,
    "comment" TEXT
);
DROP TABLE "spdx";
ALTER TABLE "new_spdx" RENAME TO "spdx";
CREATE UNIQUE INDEX "spdx_spdxId_key" ON "spdx"("spdxId");
