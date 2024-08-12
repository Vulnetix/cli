-- RedefineTables
PRAGMA defer_foreign_keys = ON;
PRAGMA foreign_keys = OFF;
CREATE TABLE "new_git_repos" (
    "fullName" TEXT NOT NULL,
    "ghid" INTEGER,
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
    "avatarUrl" TEXT,
    PRIMARY KEY ("fullName", "memberEmail")
);
INSERT INTO "new_git_repos" (
        "archived",
        "avatarUrl",
        "createdAt",
        "defaultBranch",
        "fork",
        "fullName",
        "ghid",
        "licenseName",
        "licenseSpdxId",
        "memberEmail",
        "ownerId",
        "pushedAt",
        "source",
        "template",
        "updatedAt",
        "visibility"
    )
SELECT "archived",
    "avatarUrl",
    "createdAt",
    "defaultBranch",
    "fork",
    "fullName",
    "ghid",
    "licenseName",
    "licenseSpdxId",
    "memberEmail",
    "ownerId",
    "pushedAt",
    "source",
    "template",
    "updatedAt",
    "visibility"
FROM "git_repos";
DROP TABLE "git_repos";
ALTER TABLE "new_git_repos"
    RENAME TO "git_repos";
PRAGMA foreign_keys = ON;
PRAGMA defer_foreign_keys = OFF;
