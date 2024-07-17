CREATE TABLE "new_git_repos" (
    "pk" TEXT NOT NULL,
    "fullName" TEXT NOT NULL PRIMARY KEY,
    "source" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "updatedAt" INTEGER NOT NULL,
    "pushedAt" INTEGER NOT NULL,
    "defaultBranch" TEXT NOT NULL,
    "ownerId" INTEGER NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "licenseSpdxId" TEXT,
    "licenseName" TEXT,
    "fork" INTEGER NOT NULL DEFAULT 0,
    "template" INTEGER NOT NULL DEFAULT 0,
    "archived" INTEGER NOT NULL DEFAULT 0,
    "visibility" TEXT NOT NULL,
    "avatarUrl" TEXT
);
INSERT INTO "new_git_repos" (
        "archived",
        "avatarUrl",
        "createdAt",
        "defaultBranch",
        "fork",
        "source",
        "fullName",
        "licenseName",
        "licenseSpdxId",
        "memberEmail",
        "ownerId",
        "pk",
        "pushedAt",
        "template",
        "updatedAt",
        "visibility"
    )
SELECT "archived",
    "avatarUrl",
    "createdAt",
    "defaultBranch",
    "fork",
    "GitHub" AS "source",
    "fullName",
    "licenseName",
    "licenseSpdxId",
    "memberEmail",
    "ownerId",
    "pk",
    "pushedAt",
    "template",
    "updatedAt",
    "visibility"
FROM "git_repos";
DROP TABLE "git_repos";
ALTER TABLE "new_git_repos"
    RENAME TO "git_repos";
CREATE UNIQUE INDEX "git_repos_pk_key" ON "git_repos"("pk");
