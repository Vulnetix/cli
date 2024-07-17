DROP TABLE "github_apps";
CREATE TABLE "github_apps" (
    "installationId" INTEGER NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "login" TEXT,
    "created" INTEGER NOT NULL,
    "expires" INTEGER
);
CREATE UNIQUE INDEX "github_apps_installationId_key" ON "github_apps"("installationId");
