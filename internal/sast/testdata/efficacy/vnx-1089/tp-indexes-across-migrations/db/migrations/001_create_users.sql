~>CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT,
    city TEXT,
    country TEXT,
    plan TEXT,
    created_at TIMESTAMP
);
CREATE UNIQUE INDEX users_email_idx ON users (email);
CREATE INDEX users_name_idx ON users (name);
