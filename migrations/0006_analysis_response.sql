PRAGMA defer_foreign_keys = ON;
PRAGMA foreign_keys = OFF;
CREATE TABLE "new_triage_activity" (
    "findingId" TEXT NOT NULL PRIMARY KEY,
    "createdAt" INTEGER NOT NULL,
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
    "analysisDetail" TEXT
);
INSERT INTO "new_triage_activity" (
        "analysisDetail",
        "analysisJustification",
        "analysisState",
        "createdAt",
        "cvssScore",
        "cvssVector",
        "epssPercentile",
        "epssScore",
        "findingId",
        "lastObserved",
        "remediation",
        "seen",
        "seenAt",
        "ssvc"
    )
SELECT "analysisDetail",
    "analysisJustification",
    "analysisState",
    "createdAt",
    "cvssScore",
    "cvssVector",
    "epssPercentile",
    "epssScore",
    "findingId",
    "lastObserved",
    "remediation",
    "seen",
    "seenAt",
    "ssvc"
FROM "triage_activity";
DROP TABLE "triage_activity";
ALTER TABLE "new_triage_activity"
    RENAME TO "triage_activity";
CREATE UNIQUE INDEX "triage_activity_findingId_analysisState_key" ON "triage_activity"("findingId", "analysisState");
PRAGMA foreign_keys = ON;
PRAGMA defer_foreign_keys = OFF;
