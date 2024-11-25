-- CreateTable
CREATE TABLE "ProductRepos" (
    "repoName" TEXT NOT NULL,
    "productUuid" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    PRIMARY KEY ("repoName", "productUuid")
);
-- CreateTable
CREATE TABLE "Tags" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "url" TEXT
);
-- CreateTable
CREATE TABLE "ProductTags" (
    "productUuid" TEXT NOT NULL,
    "tagsUuid" TEXT NOT NULL,
    PRIMARY KEY ("productUuid", "tagsUuid")
);
CREATE TABLE "new_Product" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "monitored" INTEGER NOT NULL DEFAULT 0,
    "monitoredSchedule" TEXT NOT NULL DEFAULT '0 7 * * mon-fri',
    "lastMonitored" INTEGER NOT NULL,
    "businessCritical" INTEGER NOT NULL DEFAULT 0,
    "productTagsUuid" TEXT,
    "ownerEmail" TEXT
);
INSERT INTO "new_Product" ("name", "uuid")
SELECT "name",
    "uuid"
FROM "Product";
DROP TABLE "Product";
ALTER TABLE "new_Product"
    RENAME TO "Product";
-- Remove memberEmail
CREATE TABLE "new_GitHubApp" (
    "installationId" INTEGER NOT NULL PRIMARY KEY,
    "orgId" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "login" TEXT,
    "created" INTEGER NOT NULL,
    "expires" INTEGER,
    "avatarUrl" TEXT
);
INSERT INTO "new_GitHubApp" (
        "accessToken",
        "avatarUrl",
        "created",
        "expires",
        "installationId",
        "login",
        "orgId"
    )
SELECT "accessToken",
    "avatarUrl",
    "created",
    "expires",
    "installationId",
    "login",
    "orgId"
FROM "GitHubApp";
DROP TABLE "GitHubApp";
ALTER TABLE "new_GitHubApp"
    RENAME TO "GitHubApp";
