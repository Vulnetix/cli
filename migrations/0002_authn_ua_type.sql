DROP TABLE IF EXISTS "sessions";
CREATE TABLE "sessions" (
    "kid" TEXT NOT NULL,
    "memberEmail" TEXT NOT NULL,
    "expiry" INTEGER NOT NULL,
    "issued" INTEGER NOT NULL,
    "secret" TEXT,
    "authn_ip" TEXT,
    "authn_ua" TEXT
);
