ALTER TABLE Finding
ADD timelineJSON TEXT;
ALTER TABLE Finding DROP COLUMN maliciousSource;
ALTER TABLE Finding
ADD malicious INTEGER;
