-- RedefineTables
PRAGMA defer_foreign_keys = ON;
PRAGMA foreign_keys = OFF;
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
    "externalReferencesJSON" TEXT,
    "componentsJSON" TEXT,
    "dependenciesJSON" TEXT
);
INSERT INTO "new_cdx" (
        "cdxId",
        "cdxVersion",
        "componentsJSON",
        "createdAt",
        "dependenciesJSON",
        "externalReferencesJSON",
        "memberEmail",
        "name",
        "repoName",
        "serialNumber",
        "source",
        "toolName",
        "version"
    )
SELECT "cdxId",
    "cdxVersion",
    "componentsJSON",
    "createdAt",
    "dependenciesJSON",
    "externalReferencesJSON",
    "memberEmail",
    "name",
    "repoName",
    "serialNumber",
    "source",
    "toolName",
    "version"
FROM "cdx";
DROP TABLE "cdx";
ALTER TABLE "new_cdx"
    RENAME TO "cdx";
CREATE UNIQUE INDEX "cdx_cdxId_key" ON "cdx"("cdxId");
CREATE TABLE "new_sarif" (
    "sarifId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL PRIMARY KEY,
    "fullName" TEXT,
    "source" TEXT NOT NULL,
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
INSERT INTO "new_sarif" (
        "analysisKey",
        "commitSha",
        "createdAt",
        "fullName",
        "memberEmail",
        "ref",
        "reportId",
        "resultsCount",
        "rulesCount",
        "sarifId",
        "source",
        "toolName",
        "toolVersion",
        "warning"
    )
SELECT "analysisKey",
    "commitSha",
    "createdAt",
    "fullName",
    "memberEmail",
    "ref",
    "reportId",
    "resultsCount",
    "rulesCount",
    "sarifId",
    "source",
    "toolName",
    "toolVersion",
    "warning"
FROM "sarif";
DROP TABLE "sarif";
ALTER TABLE "new_sarif"
    RENAME TO "sarif";
CREATE UNIQUE INDEX "sarif_sarifId_key" ON "sarif"("sarifId");
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
INSERT INTO "new_spdx" (
        "comment",
        "createdAt",
        "dataLicense",
        "documentDescribes",
        "documentNamespace",
        "memberEmail",
        "name",
        "packagesJSON",
        "relationshipsJSON",
        "repoName",
        "source",
        "spdxId",
        "spdxVersion",
        "toolName"
    )
SELECT "comment",
    "createdAt",
    "dataLicense",
    "documentDescribes",
    "documentNamespace",
    "memberEmail",
    "name",
    "packagesJSON",
    "relationshipsJSON",
    "repoName",
    "source",
    "spdxId",
    "spdxVersion",
    "toolName"
FROM "spdx";
DROP TABLE "spdx";
ALTER TABLE "new_spdx"
    RENAME TO "spdx";
CREATE UNIQUE INDEX "spdx_spdxId_key" ON "spdx"("spdxId");
PRAGMA foreign_keys = ON;
PRAGMA defer_foreign_keys = OFF;
