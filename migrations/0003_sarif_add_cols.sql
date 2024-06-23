CREATE TABLE "sarif_results" (
    "guid" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "messageText" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "locations" TEXT
);

CREATE UNIQUE INDEX "sarif_results_guid_key" ON "sarif_results"("guid");
