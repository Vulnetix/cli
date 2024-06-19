-- CreateTable
DROP TABLE IF EXISTS "audit";
CREATE TABLE "audit" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "memberEmail" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "actionTime" INTEGER NOT NULL,
    "additionalData" TEXT
);

-- CreateTable
DROP TABLE IF EXISTS "sessions";
CREATE TABLE "sessions" (
    "kid" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "expiry" INTEGER NOT NULL,
    "issued" INTEGER NOT NULL,
    "secret" TEXT,
    "authn_ip" TEXT,
    "authn_ua" INTEGER
);

-- CreateTable
DROP TABLE IF EXISTS "members";
CREATE TABLE "members" (
    "email" TEXT NOT NULL,
    "orgName" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "phoneNumber" TEXT,
    "alertNews" INTEGER NOT NULL DEFAULT 0,
    "alertOverdue" INTEGER NOT NULL DEFAULT 0,
    "alertFindings" INTEGER NOT NULL DEFAULT 0,
    "alertType" INTEGER NOT NULL DEFAULT 0
);

-- CreateTable
DROP TABLE IF EXISTS "member_keys";
CREATE TABLE "member_keys" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "memberEmail" TEXT NOT NULL,
    "keyType" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "suspend" INTEGER NOT NULL DEFAULT 0
);

-- CreateTable
DROP TABLE IF EXISTS "github_apps";
CREATE TABLE "github_apps" (
    "installationId" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "accessToken" TEXT NOT NULL,
    "created" INTEGER NOT NULL,
    "expires" INTEGER
);

-- CreateTable
DROP TABLE IF EXISTS "git_repos";
CREATE TABLE "git_repos" (
    "pk" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
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

-- CreateTable
DROP TABLE IF EXISTS "sarif";
CREATE TABLE "sarif" (
    "sarifId" INTEGER NOT NULL,
    "reportId" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "commitSha" TEXT NOT NULL,
    "ref" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "resultsCount" INTEGER NOT NULL,
    "rulesCount" INTEGER NOT NULL,
    "toolName" TEXT,
    "toolVersion" TEXT,
    "analysisKey" TEXT NOT NULL,
    "warning" TEXT
);

-- CreateIndex
CREATE UNIQUE INDEX "audit_memberEmail_key" ON "audit"("memberEmail");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_kid_key" ON "sessions"("kid");

-- CreateIndex
CREATE UNIQUE INDEX "members_email_key" ON "members"("email");

-- CreateIndex
CREATE UNIQUE INDEX "github_apps_installationId_key" ON "github_apps"("installationId");

-- CreateIndex
CREATE UNIQUE INDEX "git_repos_pk_key" ON "git_repos"("pk");

-- CreateIndex
CREATE UNIQUE INDEX "sarif_sarifId_key" ON "sarif"("sarifId");
