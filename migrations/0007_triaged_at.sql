-- RedefineTables
PRAGMA defer_foreign_keys = ON;
PRAGMA foreign_keys = OFF;
CREATE TABLE "new_triage_activity" (
    "findingId" TEXT NOT NULL,
    "createdAt" INTEGER NOT NULL,
    "triagedAt" INTEGER,
    "lastObserved" INTEGER NOT NULL,
    "seen" INTEGER NOT NULL,
    "seenAt" INTEGER,
    "cvssVector" TEXT,
    "cvssScore" TEXT,
    "epssPercentile" TEXT,
    "epssScore" TEXT,
    "ssvc" TEXT,
    "remediation" TEXT,
    "analysisState" TEXT NOT NULL,
    "analysisJustification" TEXT,
    "analysisResponse" TEXT,
    "analysisDetail" TEXT,
    "triageAutomated" INTEGER NOT NULL DEFAULT 0,
    "memberEmail" TEXT
);
INSERT INTO "new_triage_activity" (
        "analysisDetail",
        "analysisJustification",
        "analysisResponse",
        "analysisState",
        "createdAt",
        "cvssScore",
        "cvssVector",
        "epssPercentile",
        "epssScore",
        "findingId",
        "lastObserved",
        "memberEmail",
        "remediation",
        "seen",
        "seenAt",
        "ssvc",
        "triageAutomated"
    )
SELECT "analysisDetail",
    "analysisJustification",
    "analysisResponse",
    "analysisState",
    "createdAt",
    "cvssScore",
    "cvssVector",
    "epssPercentile",
    "epssScore",
    "findingId",
    "lastObserved",
    "memberEmail",
    "remediation",
    "seen",
    "seenAt",
    "ssvc",
    "triageAutomated"
FROM "triage_activity";
DROP TABLE "triage_activity";
ALTER TABLE "new_triage_activity"
    RENAME TO "triage_activity";
CREATE UNIQUE INDEX "triage_activity_findingId_key" ON "triage_activity"("findingId");
PRAGMA foreign_keys = ON;
PRAGMA defer_foreign_keys = OFF;
