CREATE TABLE IF NOT EXISTS "orgs" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL
);
INSERT INTO "orgs" ("uuid", "name")
SELECT upper(
        hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-' || '4' || substr(hex(randomblob(2)), 2) || '-' || substr('AB89', 1 + (abs(random()) % 4), 1) || substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))
    ),
    "orgname"
FROM "members";
CREATE TABLE "new_members" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "orgId" TEXT,
    "passwordHash" TEXT NOT NULL,
    "avatarUrl" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "alertNews" INTEGER NOT NULL DEFAULT 0,
    "alertOverdue" INTEGER NOT NULL DEFAULT 0,
    "alertFindings" INTEGER NOT NULL DEFAULT 0,
    "alertType" INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "new_members" (
        "uuid",
        "alertFindings",
        "alertNews",
        "alertOverdue",
        "alertType",
        "avatarUrl",
        "orgId",
        "email",
        "firstName",
        "lastName",
        "passwordHash"
    )
SELECT upper(
        hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-' || '4' || substr(hex(randomblob(2)), 2) || '-' || substr('AB89', 1 + (abs(random()) % 4), 1) || substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))
    ),
    "alertFindings",
    "alertNews",
    "alertOverdue",
    "alertType",
    "avatarUrl",
    (
        SELECT "uuid"
        FROM "orgs"
        WHERE "name" = orgName
        LIMIT 1
    ) as "orgId",
    "email",
    "firstName",
    "lastName",
    "passwordHash"
FROM "members";
DROP TABLE "members";
ALTER TABLE "new_members"
    RENAME TO "members";
CREATE UNIQUE INDEX "members_email_key" ON "members"("email");
