-- PRAGMA table_list;
-- PRAGMA table_info(Artifact);
-- DELETE FROM Artifact;
-- SELECT * FROM IntegrationConfig -- ORDER BY `date` DESC LIMIT 10;
-- UPDATE Finding SET malicious = 0;
-- SELECT * FROM SPDXInfo LIMIT 10;
-- SELECT DISTINCT malicious FROM Finding;
-- ALTER TABLE Finding DROP COLUMN malicious;
-- ALTER TABLE Finding ADD malicious INTEGER;
SELECT *
FROM Finding
WHERE cvssVectorString IS NOT NULL;
