-- CreateTable
CREATE TABLE "GitBranch" (
    "name" TEXT NOT NULL,
    "repoName" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "protected" INTEGER NOT NULL DEFAULT 0,
    "orgId" TEXT NOT NULL,
    PRIMARY KEY ("repoName", "name")
);
