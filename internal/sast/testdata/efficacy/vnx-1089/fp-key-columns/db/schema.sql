CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) NOT NULL,
    index INTEGER NOT NULL,
    unique_key VARCHAR(64),
    key_hash CHAR(64),
    index_name VARCHAR(64),
    key TEXT,
    index SMALLINT,
    key BYTEA,
    UNIQUE (key, index)
);
CREATE INDEX settings_key ON settings (key);
