CREATE TABLE "Lifecycle" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "event" TEXT NOT NULL,
    "date" DATETIME NOT NULL,
    "collectionUuid" TEXT,
    "leafUuid" TEXT,
    "productUuid" TEXT
);
CREATE TABLE "Link" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "uri" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "artifactUuid" TEXT
);
CREATE TABLE "Artifact" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "displayIdentifier" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "date" INTEGER NOT NULL,
    "bomFormat" TEXT NOT NULL,
    "inventoryTypes" TEXT NOT NULL,
    "collectionUuid" TEXT
);
CREATE TABLE "Identity" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "type" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "artifactId" TEXT,
    "collectionUuid" TEXT
);
CREATE TABLE "Collection" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "version" TEXT,
    "created" INTEGER NOT NULL
);
CREATE TABLE "Leaf" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "tei" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "productUuid" TEXT
);
CREATE TABLE "Product" (
    "uuid" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL
);
CREATE UNIQUE INDEX "Leaf_tei_key" ON "Leaf"("tei");
