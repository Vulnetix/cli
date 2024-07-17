CREATE TABLE "github_pat" (
    "keyId" INTEGER NOT NULL,
    "login" TEXT NOT NULL,
    "expires" INTEGER NOT NULL,
    "created" INTEGER NOT NULL,
    "avatarUrl" TEXT
);
CREATE UNIQUE INDEX "github_pat_keyId_key" ON "github_pat"("keyId");
