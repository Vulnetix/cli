CREATE TABLE "IntegrationConfig" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "label" TEXT,
    "created" INTEGER NOT NULL,
    "suspend" INTEGER DEFAULT 0,
    "configJSON" TEXT
);
