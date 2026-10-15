CREATE TABLE owners (
    id INTEGER PRIMARY KEY,
    first_name VARCHAR(30),
    last_name VARCHAR(30),
    city VARCHAR(80),
    telephone VARCHAR(20)
);
CREATE INDEX owners_last_name ON owners (last_name);
CREATE INDEX owners_city ON owners (city);
CREATE UNIQUE INDEX owners_phone ON owners (telephone);
